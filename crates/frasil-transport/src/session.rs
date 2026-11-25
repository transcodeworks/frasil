//! The member connection as a state machine (transport.md, sections 3.2 to
//! 3.7).
//!
//! A [`MemberSession`] is one side of one member connection. It takes the
//! control stream's messages ([`MemberSession::receive`]) and the caller's
//! decisions (offers, matches, roster check outcomes), and returns
//! [`Event`]s: messages to send on the control stream, and what the caller
//! must decide next. It holds no socket, clock or randomness: the channel
//! binding (T2) and both endpoint keys (T1) come from the binding when the
//! connection opens, and every nonce and filler comes in through a `_with`
//! method.
//!
//! The flow of one attach:
//!
//! 1. The initiator calls [`offer_with`](MemberSession::offer_with) and
//!    sends the `Offer`. The dialer initiates attach 0.
//! 2. The responder receives it ([`Event::OfferReceived`]) and calls
//!    [`respond_with`](MemberSession::respond_with) with its candidate
//!    states. It sends an `Answer`, and for attach 0 its `Identify`, or a
//!    `Refuse`.
//! 3. The initiator receives the answer ([`Event::Proved`]), and for attach
//!    0 sends its `Identify`; or a refusal ([`Event::Refused`]), after which
//!    it may offer again with [`retry_with`](MemberSession::retry_with).
//! 4. Once a side holds the other's proof for the attach and the other's
//!    `ed || kc`, it asks for the roster check of their device ID ([`Event::CheckRoster`]),
//!    and gives the outcome to [`verdict`](MemberSession::verdict), which
//!    sends `Admit` or `Detach`, or starts probation.
//!
//! Every failure of a received message closes the connection with its
//! class's code, as [`Closed`] says. The handshake runs within
//! `handshake_deadline` from the connection to the first `Admit` or
//! refusal; [`deadline`](MemberSession::deadline) checks it against the
//! caller's clock.

use crate::frame::{Message, MessageType};
use crate::member::{
    MAX_ATTACHES, MAX_OFFERS, OFFER_TAGS, ReadOffer, Reply, Role, Secret, SentOffer, identify,
    match_offer, read_offer, verify_identify,
};
use crate::messages::{Admit, Detach, Refuse, malformed};
use crate::roster::{Serving, Verdict};
use crate::{Channel, Closed, Code, HANDSHAKE_DEADLINE_SECONDS, TransportClass};
use core::borrow::Borrow;
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, KeysCommitment, Signatory};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Something the session tells its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A message to send on the control stream, in order.
    Send(Vec<u8>),
    /// An offer arrived for an attach: answer it with
    /// [`MemberSession::respond_with`].
    OfferReceived {
        /// The attach.
        attach: u32,
    },
    /// The attach's proof is done: the space and the proof state are fixed
    /// ([`MemberSession::state`]).
    Proved {
        /// The attach.
        attach: u32,
    },
    /// The other side refused the session's offer.
    Refused {
        /// The attach.
        attach: u32,
        /// The refusal's code.
        code: Code,
        /// Whether the session may offer again for the attach, with
        /// [`MemberSession::retry_with`]: after `no_common_state` or `busy`,
        /// up to 3 more offers.
        may_retry: bool,
    },
    /// The other side's `Identify` verified: its `ed || kc`, bound to this
    /// connection, and their device ID.
    Identified {
        /// The other device's `ed || kc`.
        signer: Signatory,
        /// Their device ID: the device the connection is bound to.
        device: DeviceId,
    },
    /// Run the roster check (section 3.5) for the attach, against the
    /// verifier's own current view, and give the outcome to
    /// [`MemberSession::verdict`].
    CheckRoster {
        /// The attach.
        attach: u32,
        /// The device to check: the device ID of attach 0's `Identify`.
        device: DeviceId,
    },
    /// The other side admitted the session for the attach.
    Admitted {
        /// The attach.
        attach: u32,
    },
    /// The other side detached the attach.
    Detached {
        /// The attach.
        attach: u32,
        /// The `Detach`'s code.
        code: Code,
    },
    /// The last attach is detached: close the connection with this code,
    /// `done`.
    Close(Code),
    /// A message of another type than the handshake's (1 to 6), for the
    /// caller.
    Other(Message),
}

/// Where the session stands on its own side of an attach it proved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Local {
    /// The roster check has not decided yet.
    Pending,
    /// The other device is in probation.
    Probation,
    /// The session sent `Admit`.
    Admitted,
}

enum Phase<T> {
    /// The session's offer awaits a reply; `offers` counts those sent.
    Offering { offer: SentOffer<T>, offers: usize },
    /// The session's offer was refused.
    Refused { offers: usize, may_retry: bool },
    /// The other side's offer awaits `respond_with`; `offers` counts those
    /// received, this one included.
    Offered { offer: ReadOffer, offers: usize },
    /// The session refused the other side's offer.
    Refusing { offers: usize },
    /// The proof is done.
    Proved {
        state: T,
        local: Local,
        remote_admitted: bool,
    },
    /// Detached, by either side.
    Detached,
}

/// One side of one member connection.
pub struct MemberSession<T> {
    role: Role,
    channel: Channel,
    local_endpoint: [u8; 32],
    remote_endpoint: [u8; 32],
    identity_seed: Secret,
    kc: KeysCommitment,
    th0: Option<[u8; 32]>,
    remote: Option<(Signatory, DeviceId)>,
    next_attach: u32,
    attaches: BTreeMap<u32, Phase<T>>,
    settled: bool,
}

impl<T> core::fmt::Debug for MemberSession<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemberSession")
            .field("role", &self.role)
            .field("remote", &self.remote.map(|(_, device)| device))
            .field("attaches", &self.attaches.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<T> MemberSession<T> {
    /// A session for one side of a connection the binding opened: its
    /// role, the channel binding, this side's endpoint key and the other's
    /// as the transport proved them, and this device's identity seed, which
    /// signs `Identify`, with its keys commitment `kc`, which `Identify`
    /// carries beside the Ed25519 key.
    pub fn new(
        role: Role,
        channel: Channel,
        local_endpoint: [u8; 32],
        remote_endpoint: [u8; 32],
        identity_seed: &[u8; 32],
        kc: KeysCommitment,
    ) -> Self {
        Self {
            role,
            channel,
            local_endpoint,
            remote_endpoint,
            identity_seed: Zeroizing::new(*identity_seed),
            kc,
            th0: None,
            remote: None,
            next_attach: role.parity(),
            attaches: BTreeMap::new(),
            settled: false,
        }
    }

    /// The session's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The other device's `ed || kc`, once its `Identify` verified.
    pub fn remote_signer(&self) -> Option<&Signatory> {
        self.remote.as_ref().map(|(signer, _)| signer)
    }

    /// The other device's device ID, once its `Identify` verified.
    pub fn remote_device(&self) -> Option<&DeviceId> {
        self.remote.as_ref().map(|(_, device)| device)
    }

    /// Attach 0's transcript `th_0`, once attach 0 is proved.
    pub fn transcript0(&self) -> Option<&[u8; 32]> {
        self.th0.as_ref()
    }

    /// The attach's state, once the attach is proved.
    pub fn state(&self, attach: u32) -> Option<&T> {
        match self.attaches.get(&attach)? {
            Phase::Proved { state, .. } => Some(state),
            _ => None,
        }
    }

    /// The attaches proved and not detached.
    pub fn proved(&self) -> impl Iterator<Item = (u32, &T)> {
        self.attaches
            .iter()
            .filter_map(|(attach, phase)| match phase {
                Phase::Proved { state, .. } => Some((*attach, state)),
                _ => None,
            })
    }

    /// Whether the other side admitted the session for the attach.
    pub fn admitted_by_other(&self, attach: u32) -> bool {
        matches!(
            self.attaches.get(&attach),
            Some(Phase::Proved {
                remote_admitted: true,
                ..
            })
        )
    }

    /// What the session may serve the other device on the attach: nothing
    /// before it admits it, catch-up during probation.
    pub fn serving(&self, attach: u32) -> Serving {
        match self.attaches.get(&attach) {
            Some(Phase::Proved {
                local: Local::Admitted,
                ..
            }) => Serving::Everything,
            Some(Phase::Proved {
                local: Local::Probation,
                ..
            }) => Serving::CatchUp,
            _ => Serving::Nothing,
        }
    }

    /// Whether the handshake has reached its first `Admit` or refusal.
    pub fn settled(&self) -> bool {
        self.settled
    }

    /// `handshake_deadline` (section 3.4): a close with `timeout` if
    /// `elapsed` seconds have passed since the transport's connection and
    /// the handshake has not reached its first `Admit` or refusal.
    pub fn deadline(&self, elapsed: u64) -> Option<Closed> {
        (!self.settled && elapsed >= HANDSHAKE_DEADLINE_SECONDS)
            .then(|| Closed::of(TransportClass::Timeout))
    }

    fn endpoints(&self, attach: u32) -> ([u8; 32], [u8; 32]) {
        if Role::of_attach(attach) == self.role {
            (self.local_endpoint, self.remote_endpoint)
        } else {
            (self.remote_endpoint, self.local_endpoint)
        }
    }

    fn live(&self) -> bool {
        self.attaches.values().any(|phase| {
            !matches!(
                phase,
                Phase::Detached
                    | Phase::Refused {
                        may_retry: false,
                        ..
                    }
            )
        })
    }

    /// Starts an attach: the next attach number of the session's parity
    /// (the dialer's first is 0), and its `Offer` of these states, each
    /// with its secret `k(S)`, in the order of section 3.2. `nonce` and
    /// `fillers` are fresh random bytes.
    ///
    /// # Errors
    ///
    /// `AttachLimit` once the session's attach numbers reach 1,024.
    pub fn offer_with<K: Borrow<[u8; 32]>>(
        &mut self,
        states: impl IntoIterator<Item = (T, K)>,
        nonce: [u8; 32],
        fillers: &[[u8; 32]; OFFER_TAGS],
    ) -> Result<(u32, Vec<Event>), TransportClass> {
        let attach = self.next_attach;
        if attach >= MAX_ATTACHES {
            return Err(TransportClass::AttachLimit);
        }
        self.next_attach += 2;
        let offer = SentOffer::new_with(attach, &self.channel, states, nonce, fillers);
        let send = Event::Send(offer.message().to_vec());
        self.attaches
            .insert(attach, Phase::Offering { offer, offers: 1 });
        Ok((attach, vec![send]))
    }

    /// Offers again for an attach the other side refused with
    /// `no_common_state` or `busy`, with a new nonce and the next older
    /// states (section 3.2): at most 4 offers per attach.
    ///
    /// # Errors
    ///
    /// `Malformed` if the attach was not refused so that it may retry.
    pub fn retry_with<K: Borrow<[u8; 32]>>(
        &mut self,
        attach: u32,
        states: impl IntoIterator<Item = (T, K)>,
        nonce: [u8; 32],
        fillers: &[[u8; 32]; OFFER_TAGS],
    ) -> Result<Vec<Event>, TransportClass> {
        let Some(Phase::Refused {
            offers,
            may_retry: true,
        }) = self.attaches.get(&attach)
        else {
            return Err(malformed());
        };
        let offers = offers + 1;
        let offer = SentOffer::new_with(attach, &self.channel, states, nonce, fillers);
        let send = Event::Send(offer.message().to_vec());
        self.attaches
            .insert(attach, Phase::Offering { offer, offers });
        Ok(vec![send])
    }

    /// Takes one message of the control stream, as
    /// [`crate::frame::read_frame`] read it.
    ///
    /// # Errors
    ///
    /// A failure closes the connection with the code [`Closed`] carries.
    pub fn receive(&mut self, message: &Message) -> Result<Vec<Event>, Closed> {
        match message.kind {
            MessageType::Offer => self.on_offer(message),
            MessageType::Answer | MessageType::Refuse => self.on_reply(message),
            MessageType::Identify => self.on_identify(message),
            MessageType::Admit => self.on_admit(message),
            MessageType::Detach => self.on_detach(message),
            _ => Ok(vec![Event::Other(message.clone())]),
        }
    }

    fn peek_attach(message: &Message) -> Option<u32> {
        message
            .get(1)?
            .as_unsigned()
            .ok()
            .and_then(|a| u32::try_from(a).ok())
    }

    fn on_offer(&mut self, message: &Message) -> Result<Vec<Event>, Closed> {
        let attach = Self::peek_attach(message);
        let previous = match attach.and_then(|a| self.attaches.get(&a)) {
            None => 0,
            Some(Phase::Refusing { offers }) => *offers,
            Some(_) => return Err(Closed::of(ErrorClass::Malformed)),
        };
        match read_offer(message, self.role.other(), previous) {
            Ok(offer) => {
                let attach = offer.attach;
                self.attaches.insert(
                    attach,
                    Phase::Offered {
                        offer,
                        offers: previous + 1,
                    },
                );
                Ok(vec![Event::OfferReceived { attach }])
            }
            // 2. Another revision is refused, not closed.
            Err(TransportClass::Shared(ErrorClass::RevisionMismatch)) => {
                let attach = message
                    .get(1)
                    .and_then(|a| a.as_unsigned().ok())
                    .ok_or(Closed::of(ErrorClass::Malformed))?;
                if let Ok(number) = u32::try_from(attach)
                    && number < MAX_ATTACHES
                {
                    self.attaches.insert(
                        number,
                        Phase::Refusing {
                            offers: previous + 1,
                        },
                    );
                }
                self.settled = true;
                let refuse = Refuse {
                    attach,
                    code: Code::RevisionMismatch,
                };
                Ok(vec![Event::Send(refuse.encode())])
            }
            Err(class) => Err(Closed::of(class)),
        }
    }

    /// Answers the offer of an attach (section 3.3, steps 6 and 7):
    /// `candidates` are the session's candidate states, each with its secret
    /// `k(S)`, in its order (spaces by its order, each newest first, at
    /// most 256 per space); `nonce_r` is 32 fresh random bytes. On a match
    /// it sends `Answer`, and for attach 0 its `Identify`; otherwise
    /// `Refuse` with `no_common_state`, or `busy` if the budget ran out.
    ///
    /// # Errors
    ///
    /// `Malformed` if no offer of the attach awaits an answer.
    pub fn respond_with<K: Borrow<[u8; 32]>>(
        &mut self,
        attach: u32,
        candidates: impl IntoIterator<Item = (T, K)>,
        nonce_r: [u8; 32],
    ) -> Result<Vec<Event>, TransportClass> {
        let Some(Phase::Offered { offer, offers }) = self.attaches.get(&attach) else {
            return Err(malformed());
        };
        let offers = *offers;
        let found = match_offer(offer, &self.channel, candidates);
        let found = match found {
            Ok(found) => found,
            Err(class) => {
                let code = class.code().unwrap_or(Code::NoCommonState);
                self.attaches.insert(attach, Phase::Refusing { offers });
                self.settled = true;
                let refuse = Refuse {
                    attach: attach.into(),
                    code,
                };
                return Ok(vec![Event::Send(refuse.encode())]);
            }
        };
        let (endpoint_i, endpoint_r) = self.endpoints(attach);
        let answer = found.answer_with(offer, &self.channel, &endpoint_i, &endpoint_r, nonce_r);
        let mut events = vec![Event::Send(answer.message)];
        if attach == 0 {
            self.th0 = Some(answer.transcript);
            events.push(Event::Send(identify(
                &self.identity_seed,
                &self.kc,
                &answer.transcript,
                self.role,
            )));
        }
        self.attaches.insert(
            attach,
            Phase::Proved {
                state: found.state,
                local: Local::Pending,
                remote_admitted: false,
            },
        );
        events.push(Event::Proved { attach });
        if let Some((_, device)) = self.remote {
            events.push(Event::CheckRoster { attach, device });
        }
        Ok(events)
    }

    fn on_reply(&mut self, message: &Message) -> Result<Vec<Event>, Closed> {
        let attach = Self::peek_attach(message).ok_or(Closed::of(ErrorClass::Malformed))?;
        let Some(Phase::Offering { offer, offers }) = self.attaches.get_mut(&attach) else {
            return Err(Closed::of(ErrorClass::Malformed));
        };
        let offers = *offers;
        let (endpoint_i, endpoint_r) = (self.local_endpoint, self.remote_endpoint);
        match offer.read_reply(message, &self.channel, &endpoint_i, &endpoint_r)? {
            Reply::Refused(code) => {
                let may_retry =
                    matches!(code, Code::NoCommonState | Code::Busy) && offers < MAX_OFFERS;
                self.attaches
                    .insert(attach, Phase::Refused { offers, may_retry });
                self.settled = true;
                Ok(vec![Event::Refused {
                    attach,
                    code,
                    may_retry,
                }])
            }
            Reply::Answered { index, transcript } => {
                let state = offer
                    .take_state(index)
                    .expect("a verified index names a real state");
                let mut events = Vec::new();
                if attach == 0 {
                    self.th0 = Some(transcript);
                    // 5. For attach 0: send Identify.
                    events.push(Event::Send(identify(
                        &self.identity_seed,
                        &self.kc,
                        &transcript,
                        self.role,
                    )));
                }
                self.attaches.insert(
                    attach,
                    Phase::Proved {
                        state,
                        local: Local::Pending,
                        remote_admitted: false,
                    },
                );
                events.push(Event::Proved { attach });
                if let Some((_, device)) = self.remote {
                    events.push(Event::CheckRoster { attach, device });
                }
                Ok(events)
            }
        }
    }

    fn on_identify(&mut self, message: &Message) -> Result<Vec<Event>, Closed> {
        // Identify is sent once per connection, after attach 0's proof.
        let (Some(th0), None) = (self.th0, self.remote) else {
            return Err(Closed::of(ErrorClass::Malformed));
        };
        let signer = verify_identify(message, &th0, self.role.other())?;
        // 9. The roster check is for the device ID of ed and kc.
        let device = signer.device_id();
        self.remote = Some((signer, device));
        let mut events = vec![Event::Identified { signer, device }];
        for (attach, phase) in &self.attaches {
            if let Phase::Proved {
                local: Local::Pending,
                ..
            } = phase
            {
                events.push(Event::CheckRoster {
                    attach: *attach,
                    device,
                });
            }
        }
        Ok(events)
    }

    fn on_admit(&mut self, message: &Message) -> Result<Vec<Event>, Closed> {
        let admit = Admit::read(message)?;
        let attach = u32::try_from(admit.attach).map_err(|_| Closed::of(ErrorClass::Malformed))?;
        match self.attaches.get_mut(&attach) {
            Some(Phase::Proved {
                remote_admitted, ..
            }) if !*remote_admitted => {
                *remote_admitted = true;
                Ok(vec![Event::Admitted { attach }])
            }
            // It crossed the `Detach` that ended the attach.
            Some(Phase::Detached) => Ok(Vec::new()),
            _ => Err(Closed::of(ErrorClass::Malformed)),
        }
    }

    fn on_detach(&mut self, message: &Message) -> Result<Vec<Event>, Closed> {
        let detach = Detach::read(message)?;
        let attach = u32::try_from(detach.attach).map_err(|_| Closed::of(ErrorClass::Malformed))?;
        match self.attaches.get(&attach) {
            None => Err(Closed::of(ErrorClass::Malformed)),
            // Both sides detached the attach at the same moment.
            Some(Phase::Detached) => Ok(Vec::new()),
            Some(_) => {
                self.attaches.insert(attach, Phase::Detached);
                self.settled = true;
                let mut events = vec![Event::Detached {
                    attach,
                    code: detach.code,
                }];
                if !self.live() {
                    events.push(Event::Close(Code::Done));
                }
                Ok(events)
            }
        }
    }

    /// Gives the roster check's outcome for an attach (section 3.5), at
    /// first or at the re-check (section 3.7): `Admit` sends `Admit` once;
    /// `Detach` sends `Detach` with its code before anything more is sent;
    /// `Probation` serves only catch-up until the next outcome.
    ///
    /// # Errors
    ///
    /// `Malformed` if the attach is not proved, or is detached.
    pub fn verdict(&mut self, attach: u32, verdict: Verdict) -> Result<Vec<Event>, TransportClass> {
        let Some(Phase::Proved { local, .. }) = self.attaches.get_mut(&attach) else {
            return Err(malformed());
        };
        match verdict {
            Verdict::Admit if *local == Local::Admitted => Ok(Vec::new()),
            Verdict::Admit => {
                *local = Local::Admitted;
                self.settled = true;
                Ok(vec![Event::Send(
                    Admit {
                        attach: attach.into(),
                    }
                    .encode(),
                )])
            }
            Verdict::Probation => {
                *local = Local::Probation;
                Ok(Vec::new())
            }
            Verdict::Detach(code) => self.detach(attach, code),
        }
    }

    /// Detaches an attach with a code: `done` for an attach no longer
    /// wanted, or the roster check's. When the last attach is detached,
    /// the connection closes with `done`.
    ///
    /// # Errors
    ///
    /// `Malformed` if the attach does not exist or is detached.
    pub fn detach(&mut self, attach: u32, code: Code) -> Result<Vec<Event>, TransportClass> {
        match self.attaches.get(&attach) {
            None | Some(Phase::Detached) => return Err(malformed()),
            Some(_) => {}
        }
        self.attaches.insert(attach, Phase::Detached);
        self.settled = true;
        let mut events = vec![Event::Send(
            Detach {
                attach: attach.into(),
                code,
            }
            .encode(),
        )];
        if !self.live() {
            events.push(Event::Close(Code::Done));
        }
        Ok(events)
    }
}
