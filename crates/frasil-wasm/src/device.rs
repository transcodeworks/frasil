//! The device, as a JavaScript class: `frasil::Device` over the platform of
//! [`crate::platform`], with its upkeep on the browser's event loop and its
//! peer connections over the browser's `WebSocket` and `fetch`
//! (`frasil::browser`).
//!
//! A device is made with a store and an unlock key, and gives its 235-byte
//! sealed device keys, which the TypeScript layer keeps beside the store;
//! opened again from them and the same unlock key, it loads every space the
//! store keeps (at-rest.md, "Sealed device keys", "Continuity").
//!
//! Besides what `frasil::Device` does, the class carries the engine's
//! direct grant (roster.md, "Changes") and what goes with it, under names
//! the TypeScript layer gathers as `device.advanced`: admission by code
//! needs a nearby connection, which a browser does not have.
//!
//! Recovery (identity.md, "Recovery"): `createRecoverySheet` adds a
//! recovery key to the device's person, and `Device.recover` makes a new
//! device from a sheet's text and a peer. Passkeys are not bound here yet:
//! `frasil::Device::add_passkey` and `frasil::Device::recover_from_passkey`
//! take a `frasil::Passkey`, whose `register` and `assert` map to
//! `navigator.credentials.create` and `navigator.credentials.get` with the
//! PRF extension (identity.md, "The passkey ceremony"); a JavaScript object
//! that makes those calls, wrapped as a `frasil::Passkey`, is the seam.

use crate::callback::confirm;
use crate::convert::{Obj, array, byte_strings, bytes, bytes_in, exact, field, hex, id, number};
use crate::error::{Js, invalid};
use crate::events::Events;
use crate::peer::Peer;
use crate::platform::{JsKeys, platform};
use crate::promise;
use crate::space::Space;
use frasil::advanced::public_keys::{self, DeviceId, DeviceKeys};
use frasil::advanced::{AdapterRegistry, Engine};
use frasil::browser::{BrowserConnect, BrowserTasks};
use frasil::{Level, Options, SpaceId};
use frasil_events::EventId;
use frasil_space::{HistoryMode, Via};
use js_sys::{Function, Promise};
use std::cell::RefCell;
use std::sync::Arc;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

fn unlock(mut value: Vec<u8>) -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let key = exact::<32>(&value, "the unlock key").map(Zeroizing::new);
    zeroize::Zeroize::zeroize(&mut value);
    key
}

fn event(space: SpaceId) -> EventId {
    EventId(*space.as_bytes())
}

fn space_id(text: &str) -> Result<SpaceId, JsValue> {
    id::<SpaceId>(text)
}

/// The person ID sealed device keys name, read before they are opened
/// (at-rest.md, "Sealing and opening the device keys", steps 1 to 4 need no
/// key): `None` for a device member's, whose 32 bytes are zero. The store
/// keeps the keys of one device, so the person they name is the person the
/// application expects.
fn person_of(sealed: &[u8]) -> Option<[u8; 32]> {
    let person: [u8; 32] = sealed.get(34..66)?.try_into().ok()?;
    (person != [0; 32]).then_some(person)
}

/// The options every browser device runs with: its tasks and its
/// connections are the browser's, and `store` keeps its sealed keys when
/// they are sealed again.
fn browser_options(store: JsValue) -> Options {
    // A browser runs this module on one thread: the Arcs only satisfy the
    // options' types.
    #[allow(clippy::arc_with_non_send_sync)]
    let options = Options::new()
        .tasks(Arc::new(BrowserTasks))
        .connect_with(Arc::new(BrowserConnect))
        .keep_keys(Arc::new(JsKeys::new(store)));
    options
}

/// A device: its keys, its store, the spaces it holds, and its connections.
#[wasm_bindgen]
pub struct Device {
    pub(crate) inner: frasil::Device,
}

impl Device {
    pub(crate) fn inner(&self) -> &frasil::Device {
        &self.inner
    }
}

#[wasm_bindgen]
impl Device {
    /// Opens the device whose keys `sealedKeys` holds, over the store it was
    /// made with, or makes a new one over `store` when `sealedKeys` is
    /// `undefined`, its keys sealed under the 32-byte `unlockKey`. Resolves
    /// to `{ device, sealedKeys }`; keep `sealedKeys` to open it again.
    pub fn open(
        store: JsValue,
        unlock_key: Vec<u8>,
        sealed_keys: Option<Vec<u8>>,
        options: JsValue,
    ) -> Promise {
        promise(async move {
            let platform = platform(store.clone(), &options)?;
            let unlock_key = unlock(unlock_key)?;
            let adapters = AdapterRegistry::with_builtins();
            let (engine, sealed) = match sealed_keys {
                Some(sealed) => {
                    let person = person_of(&sealed);
                    let engine = Engine::open_as(platform, &sealed, &unlock_key, person, adapters)
                        .await
                        .js()?;
                    (engine, sealed)
                }
                None => {
                    let (engine, sealed) =
                        Engine::create(platform, &unlock_key, adapters).await.js()?;
                    (engine, sealed.to_vec())
                }
            };
            let device = frasil::Device::from_engine(engine, browser_options(store)).js()?;
            Ok(Obj::new()
                .set("device", Device { inner: device })
                .set("sealedKeys", bytes(&sealed))
                .build())
        })
    }

    /// Makes a new device of a person from a recovery sheet's `text`, over a
    /// `store` that holds no device, its keys sealed under the 32-byte
    /// `unlockKey`: it connects to the peer at `peerUrl`, which holds the
    /// person's personal space, fetches the space through the recovery
    /// key's entry, signs itself into the person's list, and reaches every
    /// space the personal space records a recovery entry of (identity.md,
    /// "Recovery"). Resolves to `{ device, sealedKeys }`: keep `sealedKeys`
    /// to open it again. Rejects with `invalid_sheet` for a secret that does
    /// not read, `credential_refused` when the peer holds no entry of the
    /// sheet's key, `not_on_list`, or `timeout`.
    pub fn recover(
        store: JsValue,
        unlock_key: Vec<u8>,
        sheet: String,
        peer_url: String,
        options: JsValue,
    ) -> Promise {
        promise(async move {
            let platform = platform(store.clone(), &options)?;
            let unlock_key = unlock(unlock_key)?;
            let sheet = frasil::RecoverySheet::read(&sheet).js()?;
            let (engine, _) =
                Engine::create(platform, &unlock_key, AdapterRegistry::with_builtins())
                    .await
                    .js()?;
            let device = frasil::Device::from_engine(engine, browser_options(store)).js()?;
            let sealed = match device
                .recover_from_sheet(&unlock_key, sheet, &peer_url)
                .await
            {
                Ok(sealed) => sealed,
                Err(error) => {
                    let _ = device.close().await;
                    return Err(error).js();
                }
            };
            Ok(Obj::new()
                .set("device", Device { inner: device })
                .set("sealedKeys", bytes(&sealed))
                .build())
        })
    }

    /// Adds a recovery key to this device's person and resolves to its
    /// sheet, `{ text, secret, person, personalSpace }`: show or print
    /// `text` once, since the device forgets the secret. Rejects with
    /// `not_allowed` for a device of no person.
    #[wasm_bindgen(js_name = createRecoverySheet)]
    pub fn create_recovery_sheet(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let sheet = device.create_recovery_sheet().await.js()?;
            Ok(Obj::new()
                .set("text", sheet.text().as_str())
                .set("secret", sheet.secret())
                .set("person", sheet.person().to_string())
                .set("personalSpace", sheet.personal_space().to_string())
                .build())
        })
    }

    /// The device's ID, by which spaces name it as a member: 64 hex digits.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// Asks connected peers again about a retained erasure.
    #[wasm_bindgen(js_name = retryErasure)]
    pub fn retry_erasure(&self, space: String) -> Result<Promise, JsValue> {
        let space = crate::convert::id::<frasil::SpaceId>(&space)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            device.retry_erasure(space).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Gives up a space this device dropped for its own erasure: it no
    /// longer waits for each peer to answer `erased`, and forgets what it
    /// kept of the space, which may live on at the peers that did not
    /// answer.
    #[wasm_bindgen(js_name = giveUpSpace)]
    pub fn give_up_space(&self, space: String) -> Result<Promise, JsValue> {
        let space = crate::convert::id::<frasil::SpaceId>(&space)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            device.give_up_space(space).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Creates a space that this device administers, and presents it to
    /// every peer the device is connected to.
    #[wasm_bindgen(js_name = createSpace)]
    pub fn create_space(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move { Ok(Space::from(device.create_space().await.js()?).into()) })
    }

    /// Creates a space whose descriptor names `kind`, what kind of space
    /// the application makes; `invalid` for a kind that is empty or longer
    /// than 255 bytes.
    #[wasm_bindgen(js_name = createSpaceOfKind)]
    pub fn create_space_of_kind(&self, kind: String) -> Promise {
        let device = self.inner.clone();
        promise(
            async move { Ok(Space::from(device.create_space_of_kind(&kind).await.js()?).into()) },
        )
    }

    /// A 32-byte key for the application's own data on this device, one
    /// per `purpose` (at-rest.md, "Application keys").
    #[wasm_bindgen(js_name = deriveKey)]
    pub fn derive_key(&self, purpose: String) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let key = device.derive_key(&purpose).await.js()?;
            Ok(js_sys::Uint8Array::from(&key[..]).into())
        })
    }

    /// A space the device holds; `unknown_space` if it holds none of this ID.
    pub fn space(&self, space: String) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            Ok(Space::from(device.space(space).await.js()?).into())
        }))
    }

    /// Every space the device holds.
    pub fn spaces(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            Ok(array(device.spaces().await, |space| {
                Space::from(space).into()
            }))
        })
    }

    /// Connects to an always-on peer at its URL (`https://…`, or `http://`
    /// to a loopback host) and keeps every space the device holds there.
    /// Resolves once the handshake completes.
    pub fn connect(&self, url: String) -> Promise {
        let device = self.inner.clone();
        promise(async move { Ok(Peer::from(device.connect(&url).await.js()?).into()) })
    }

    /// The peers the device has connected to, open or closed.
    pub fn peers(&self) -> JsValue {
        array(self.inner.peers(), |peer| Peer::from(peer).into())
    }

    /// The device's events, from now on.
    pub fn events(&self) -> Events {
        Events::from(self.inner.events())
    }

    /// Joins a space by an invite link that `Space.inviteLink` made
    /// (ext-invite-links.md): fetches the link's drop from the peer it
    /// names, or a peer this device is connected to, and the space with it.
    /// `confirm(code, inviter)` is called with an empty code and the
    /// inviting device's ID, and returns `true`, or a promise of `true`, for
    /// the person's consent. `name` is what the inviting side shows for this
    /// device. Resolves to the space.
    pub fn join(&self, link: String, name: String, confirm_with: Function) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let space = device
                .join(&link, &name, move |code, inviter| {
                    confirm(confirm_with, code, inviter)
                })
                .await
                .js()?;
            Ok(Space::from(space).into())
        })
    }

    /// Joins a space through an exchange mailbox at the peer at `peerUrl`
    /// (admission.md, "Without a nearby connection"). Resolves to a
    /// `Joining`: show its `text` as a QR code for an administrator to
    /// enter in `Space.admit`; then `confirm(code, adminName)` is called
    /// with the six-digit code both screens show and returns `true`, or a
    /// promise of `true`, when the person saw it on both. `joined()` waits for
    /// the space.
    #[wasm_bindgen(js_name = joinViaPeer)]
    pub fn join_via_peer(&self, peer_url: String, name: String, confirm_with: Function) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let joining = device
                .join_via_peer(&peer_url, &name, move |code, host| {
                    confirm(confirm_with, code, host)
                })
                .await
                .js()?;
            Ok(Joining {
                inner: RefCell::new(Some(joining)),
            }
            .into())
        })
    }

    /// Joins `person`, the person's ID, as its new device through an
    /// exchange mailbox at the peer at `peerUrl` (admission.md, "A person's
    /// new device"); a device of another person that answers adds this
    /// device to no list, and `joined()` rejects with `wrong_person`. Resolves
    /// to a `JoiningPerson`: show its `text` as a QR code for a device of
    /// the person to enter in `Device.admitDevice`; then
    /// `confirm(code, otherName)` is called with the six-digit code both
    /// screens show and returns `true`, or a promise of `true`, when the
    /// person saw it on both. `unlockKey` is the 32-byte key this device was
    /// opened with: once admitted, its keys are sealed again under it to
    /// name the person, and kept as `makePerson` keeps them. `joined()`
    /// waits for the person's spaces.
    #[wasm_bindgen(js_name = joinPersonViaPeer)]
    pub fn join_person_via_peer(
        &self,
        peer_url: String,
        person: String,
        name: String,
        unlock_key: Vec<u8>,
        confirm_with: Function,
    ) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let person = id::<frasil::MemberId>(&person)?;
            let unlock_key = unlock(unlock_key)?;
            let joining = device
                .join_person_via_peer(&peer_url, person, &name, &unlock_key, move |code, other| {
                    confirm(confirm_with, code, other)
                })
                .await
                .js()?;
            Ok(JoiningPerson {
                inner: RefCell::new(Some(joining)),
            }
            .into())
        })
    }

    /// Adds the device whose `JoiningPerson.text` a new device shows to
    /// this device's person, through the exchange mailbox at the peer that
    /// text names. `confirm(code, newName)` is called with the six-digit
    /// code both screens show and returns `true`, or a promise of `true`,
    /// when the person saw it on both. `name` is what the new device's
    /// screen shows for this device.
    #[wasm_bindgen(js_name = admitDevice)]
    pub fn admit_device(&self, text: String, name: String, confirm_with: Function) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            device
                .admit_device(&text, &name, move |code, other| {
                    confirm(confirm_with, code, other)
                })
                .await
                .js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Grants an already authenticated device administrator access to
    /// spaces, at `rank`, at most this device's own in each.
    #[wasm_bindgen(js_name = admitSpacesViaPeer)]
    pub fn admit_spaces_via_peer(
        &self,
        url: String,
        known_space: String,
        member: String,
        rank: u8,
        spaces: Vec<String>,
        progress: Option<Function>,
    ) -> Result<Promise, JsValue> {
        let known_space = space_id(&known_space)?;
        let member = id::<frasil::MemberId>(&member)?;
        let spaces = spaces
            .iter()
            .map(|space| space_id(space))
            .collect::<Result<Vec<_>, _>>()?;
        let device = self.inner.clone();
        Ok(promise(async move {
            let reports = device
                .admit_spaces_via_peer(&url, known_space, member, rank, &spaces, |report| {
                    if let Some(callback) = &progress {
                        let _ = callback.call1(&JsValue::UNDEFINED, &admission_out(report));
                    }
                })
                .await
                .js()?;
            Ok(array(&reports, admission_out))
        }))
    }

    /// Collects and verifies administrator welcomes from a known approver.
    #[wasm_bindgen(js_name = receiveSpacesViaPeer)]
    pub fn receive_spaces_via_peer(
        &self,
        url: String,
        approver: String,
        spaces: Vec<String>,
        progress: Option<Function>,
    ) -> Result<Promise, JsValue> {
        let approver = id::<frasil::MemberId>(&approver)?;
        let spaces = spaces
            .iter()
            .map(|space| space_id(space))
            .collect::<Result<Vec<_>, _>>()?;
        let device = self.inner.clone();
        Ok(promise(async move {
            let reports = device
                .receive_spaces_via_peer(&url, approver, &spaces, |report| {
                    if let Some(callback) = &progress {
                        let _ = callback.call1(&JsValue::UNDEFINED, &admission_out(report));
                    }
                })
                .await
                .js()?;
            Ok(array(&reports, admission_out))
        }))
    }

    /// The device's person: 64 hex digits; `null` for a device of no
    /// person.
    pub fn person(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            Ok(device
                .person()
                .await
                .map_or(JsValue::NULL, |person| JsValue::from(person.to_string())))
        })
    }

    /// The personal space of the device's person: 64 hex digits; `null`
    /// for a device of no person, and while the device cannot tell which
    /// space it is.
    #[wasm_bindgen(js_name = personalSpace)]
    pub fn personal_space(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            Ok(device
                .personal_space()
                .await
                .map_or(JsValue::NULL, |space| JsValue::from(space.to_string())))
        })
    }

    /// Signs a request to an application's server (ext-app-requests.md):
    /// `subject` is the access token's `sub`, `url` the absolute URL, and
    /// `body` the exact bytes sent. Resolves to the headers to add, as
    /// `[name, value]` pairs; they live 60 seconds.
    #[wasm_bindgen(js_name = signRequest)]
    pub fn sign_request(
        &self,
        subject: String,
        method: String,
        url: String,
        body: Vec<u8>,
    ) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let headers = device
                .sign_request(&subject, &method, &url, &body)
                .await
                .js()?;
            Ok(array(headers, |(name, value)| {
                js_sys::Array::of2(&JsValue::from(name), &JsValue::from(value)).into()
            }))
        })
    }

    /// Takes another device, by its ID, off this device's person's device
    /// list, so it reaches none of the person's spaces any more, and
    /// removes it from each space this device administers that grants it
    /// directly.
    #[wasm_bindgen(js_name = removeDevice)]
    pub fn remove_device(&self, device_id: String) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&device_id)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            device.remove_device(member).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// The list delivery of this device's person (ext-app-requests.md):
    /// the body of a signed `PUT /frasil/p1/device-list`, as a
    /// `Uint8Array`.
    #[wasm_bindgen(js_name = listDelivery)]
    pub fn list_delivery(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move { Ok(bytes(&device.list_delivery().await.js()?)) })
    }

    /// Sets what the device does about checkpoints by itself (roster.md,
    /// 3.15.7 Clients): `{ propose, forget, rosterEvents, frameBytes }`,
    /// each field left out taking the default's value.
    #[wasm_bindgen(js_name = setCheckpointPolicy)]
    pub fn set_checkpoint_policy(&self, policy: JsValue) -> Result<(), JsValue> {
        let policy = crate::checkpoints::policy_in(&policy)?;
        self.inner.set_checkpoint_policy(policy);
        Ok(())
    }

    /// The device's checkpoint policy: `{ propose, forget, rosterEvents,
    /// frameBytes }`.
    #[wasm_bindgen(js_name = checkpointPolicy)]
    pub fn checkpoint_policy(&self) -> JsValue {
        crate::checkpoints::policy_out(&self.inner.engine().checkpoint_policy())
    }

    /// Proposes a checkpoint of this device's person's device list now
    /// (identity.md, 3.16 List checkpoints). Resolves to its ID.
    #[wasm_bindgen(js_name = proposeListCheckpoint)]
    pub fn propose_list_checkpoint(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let id = device.propose_list_checkpoint().await.js()?;
            Ok(JsValue::from(id.to_string()))
        })
    }

    /// The checkpoints of this device's person's device list: `{ inEffect,
    /// pending, forgot, rivals }`, each pending one `{ id, waitingFor }`.
    /// For a device of no person, none.
    #[wasm_bindgen(js_name = listCheckpoints)]
    pub fn list_checkpoints(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            Ok(crate::checkpoints::list_status_out(
                &device.list_checkpoints().await,
            ))
        })
    }

    /// Closes the device: stops its upkeep and its connections.
    pub fn close(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            device.close().await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    // ---- Advanced: the engine's direct grant, and what goes with it ----

    /// Makes a person of this device (identity.md, "Making a person"): the
    /// device list's first event and the personal space. Its keys are sealed
    /// again under the 32-byte `unlockKey` to name the person, and kept
    /// through the store's `saveSealedKeys` in place of the old ones.
    /// Resolves to `{ person, personalSpace }`. Idempotent: for a device of
    /// a person already, it resolves to `{ person }` alone, and the keys
    /// kept stay.
    #[wasm_bindgen(js_name = makePerson)]
    pub fn make_person(&self, unlock_key: Vec<u8>) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let unlock_key = unlock(unlock_key)?;
            if let Some(person) = device.person().await {
                return Ok(Obj::new().set("person", person.to_string()).build());
            }
            let person = device.make_person(&unlock_key).await.js()?;
            let made = Obj::new().set("person", person.to_string());
            Ok(match device.engine().personal_space().await {
                Some(space) => made.set("personalSpace", hex(&space.0)),
                None => made,
            }
            .build())
        })
    }

    /// Pauses the sync of these spaces, by their IDs, with always-on peers,
    /// such as every space of one library: no store and no fetch until
    /// `resumeSync`.
    #[wasm_bindgen(js_name = pauseSync)]
    pub fn pause_sync(&self, spaces: Vec<String>) -> Result<(), JsValue> {
        let spaces = spaces
            .iter()
            .map(|space| space_id(space))
            .collect::<Result<Vec<_>, _>>()?;
        self.inner.pause_sync(spaces);
        Ok(())
    }

    /// Resumes the sync of these spaces, by their IDs, with always-on
    /// peers: each catches up.
    #[wasm_bindgen(js_name = resumeSync)]
    pub fn resume_sync(&self, spaces: Vec<String>) -> Result<(), JsValue> {
        let spaces = spaces
            .iter()
            .map(|space| space_id(space))
            .collect::<Result<Vec<_>, _>>()?;
        self.inner.resume_sync(spaces);
        Ok(())
    }

    /// Keeps a library ticket for the next space this device creates at a
    /// peer that requires one (ext-libraries.md). A ticket attaches one
    /// space.
    #[wasm_bindgen(js_name = setLibraryTicket)]
    pub fn set_library_ticket(&self, ticket: Vec<u8>) -> Result<(), JsValue> {
        self.inner.set_library_ticket(ticket).js()
    }

    /// Hands the device a deposit grant for the peer at `peer`, the bytes
    /// the library's issuer gave the application (ext-deposit-tokens.md,
    /// 3.1.1). The device never reads, stores or shows it: within the hour
    /// it draws one batch of tokens with it there, then forgets it.
    #[wasm_bindgen(js_name = giveDepositGrant)]
    pub fn give_deposit_grant(&self, peer: String, grant: Vec<u8>) {
        self.inner.give_deposit_grant(&peer, grant);
    }

    /// How many deposit tokens the device holds for the peer at `peer`:
    /// `{held, paused, distrusted, grant}` (ext-deposit-tokens.md, 3.12).
    #[wasm_bindgen(js_name = depositTokens)]
    pub fn deposit_tokens(&self, peer: String) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            let tokens = device.deposit_tokens(&peer).await;
            Ok(Obj::new()
                .set("held", JsValue::from(tokens.held as f64))
                .set("paused", tokens.paused)
                .set("distrusted", tokens.distrusted)
                .set("grant", tokens.grant)
                .build())
        })
    }

    /// Trusts the deposit keys of the peer at `peer` again after a
    /// `depositPeerDistrusted` event with `key_inconsistent`: the device
    /// learns them anew (ext-deposit-tokens.md, 3.2).
    #[wasm_bindgen(js_name = trustDepositKeys)]
    pub fn trust_deposit_keys(&self, peer: String) -> Promise {
        let device = self.inner.clone();
        promise(async move {
            device.trust_deposit_keys(&peer).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// How many deposits in device mailboxes, such as welcomes, the device
    /// keeps to send again (transport.md, "A sender keeps what was
    /// refused").
    #[wasm_bindgen(js_name = waitingDeposits)]
    pub fn waiting_deposits(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move { Ok(JsValue::from(device.waiting_deposits().await as f64)) })
    }

    /// The device's three public keys, 3,200 bytes, as a direct grant
    /// carries them (roster.md, "A device's keys"). They name no device: a
    /// device that grants this one names it by its ID, which they hash to.
    #[wasm_bindgen(js_name = deviceKeys)]
    pub fn device_keys(&self) -> Vec<u8> {
        public_keys::encode(self.inner.engine().public_keys()).unwrap_or_default()
    }

    /// `"Current"`, or `"Restored"`: the store is not the one the device last
    /// wrote, and it syncs each space before it writes there.
    pub fn continuity(&self) -> Promise {
        let device = self.inner.clone();
        promise(async move { Ok(JsValue::from_str(device.engine().continuity().await.name())) })
    }

    /// Starts holding a space this device was granted directly, before it
    /// holds any of its events. A peer connection opened afterwards syncs
    /// it. Resolves to the space.
    pub fn follow(&self, space: String) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            device.engine().follow(event(space)).await;
            Ok(Space::from(device.space(space).await.js()?).into())
        }))
    }

    /// Grants a device directly (roster.md, "Changes"): its ID, its keys as
    /// `deviceKeys()` gives them, which must hash to that ID (`NotCommitted`
    /// otherwise), a level (`"read"`, `"write"` or `"administer"`), and
    /// `"with-history"` or `"from-now-on"`. Resolves to the roster event's
    /// ID. No admission step precedes it, so the grant's `via` is `none`
    /// (admission.md, 2.1 The admission event).
    #[wasm_bindgen(js_name = grantDevice)]
    pub fn grant_device(
        &self,
        space: String,
        member: String,
        keys: JsValue,
        level: String,
        history: String,
    ) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let member = id::<frasil::MemberId>(&member)?;
        let keys = device_keys(&keys, &member)?;
        let level = Level::from_name(&level)
            .ok_or_else(|| invalid("the level is \"read\", \"write\" or \"administer\"."))?;
        let history = match history.as_str() {
            "with-history" => HistoryMode::WithHistory,
            "from-now-on" => HistoryMode::FromNowOn,
            _ => return Err(invalid("history is \"with-history\" or \"from-now-on\".")),
        };
        let device = self.inner.clone();
        Ok(promise(async move {
            let id = device
                .engine()
                .grant_device(event(space), keys, level, history, Via::None)
                .await
                .js()?;
            Ok(JsValue::from_str(&hex(&id.0)))
        }))
    }

    /// Grants a guest (ext-guests.md, "The guest preset"): its ID, its keys
    /// as `deviceKeys()` gives them, which must hash to that ID, and its
    /// terms `{ level, session, lifetime,
    /// nothingAtRest, history }`: `"read"` or `"write"`, the session's 16
    /// bytes, the session's lifetime in seconds if it ends by itself,
    /// whether its device keeps nothing at rest, and `"from-now-on"`, the
    /// default, or `"with-history"`. Resolves to the roster event's ID.
    #[wasm_bindgen(js_name = grantGuest)]
    pub fn grant_guest(
        &self,
        space: String,
        member: String,
        keys: JsValue,
        terms: JsValue,
    ) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let member = id::<frasil::MemberId>(&member)?;
        let keys = device_keys(&keys, &member)?;
        let level = field(&terms, "level")?
            .as_string()
            .and_then(|name| Level::from_name(&name))
            .filter(|level| *level != Level::Administer)
            .ok_or_else(|| invalid("a guest's level is \"read\" or \"write\"."))?;
        let session = bytes_in(&field(&terms, "session")?)
            .ok_or_else(|| invalid("the session is a Uint8Array of 16 bytes."))?;
        let session: [u8; 16] = exact(&session, "the session")?;
        let mut preset = frasil_space::ext_guests::Preset::new(level, session);
        preset.nothing_at_rest = field(&terms, "nothingAtRest")?.is_truthy();
        preset.history = match field(&terms, "history")?.as_string().as_deref() {
            None | Some("from-now-on") => HistoryMode::FromNowOn,
            Some("with-history") => HistoryMode::WithHistory,
            Some(_) => return Err(invalid("history is \"with-history\" or \"from-now-on\".")),
        };
        let lifetime = field(&terms, "lifetime")?;
        if !lifetime.is_undefined() {
            let seconds = lifetime
                .as_f64()
                .filter(|s| s.is_finite() && *s >= 1.0)
                .ok_or_else(|| invalid("the lifetime is a number of seconds."))?;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let seconds = seconds as u64;
            if seconds > frasil_space::ext_guests::SESSION_LIFETIME_MAX {
                return Err(invalid("a session lasts at most 30 days."));
            }
            let wall = self
                .inner
                .engine()
                .platform()
                .clock
                .wall()
                .ok_or_else(|| invalid("a session's end needs the wall clock."))?;
            preset.expires_at = Some(wall.saturating_add(seconds));
        }
        let device = self.inner.clone();
        Ok(promise(async move {
            let id = device
                .engine()
                .grant_guest(event(space), keys, &preset)
                .await
                .js()?;
            Ok(JsValue::from_str(&hex(&id.0)))
        }))
    }

    /// The space's signed events this device holds, in canonical order:
    /// what another device takes with `ingest`.
    #[wasm_bindgen(js_name = signedEvents)]
    pub fn signed_events(&self, space: String) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            let events = device.engine().events(&event(space)).await;
            Ok(array(events, |signed| bytes(&signed)))
        }))
    }

    /// Takes a space's signed events from another party. Resolves to
    /// `{ placed, wanted, refused }`: how many were newly placed, how many
    /// parents are still wanted, and `[index, class]` for each refused.
    pub fn ingest(&self, space: String, events: JsValue) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let events = byte_strings(&events, "the events")?;
        let device = self.inner.clone();
        Ok(promise(async move {
            let ingested = device.engine().ingest(event(space), events).await.js()?;
            Ok(Obj::new()
                .set("placed", number(ingested.placed.len()))
                .set("wanted", number(ingested.wanted.len()))
                .set(
                    "refused",
                    array(ingested.refused, |(index, class)| {
                        js_sys::Array::of2(&number(index), &JsValue::from_str(class)).into()
                    }),
                )
                .build())
        }))
    }

    /// How many of the device's changes in the space no peer has
    /// acknowledged yet.
    pub fn outbox(&self, space: String) -> Result<Promise, JsValue> {
        let space = space_id(&space)?;
        let device = self.inner.clone();
        Ok(promise(async move {
            Ok(number(device.engine().outbox(&event(space)).await.len()))
        }))
    }
}

/// A newcomer's admission through an exchange mailbox, waiting for an
/// administrator to enter its text.
#[wasm_bindgen]
pub struct Joining {
    /// Taken by `joined()`.
    inner: RefCell<Option<frasil::Joining>>,
}

#[wasm_bindgen]
impl Joining {
    /// The text an administrator enters in `Space.admit`: show it as a QR
    /// code. Empty once `joined()` was called.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.inner
            .try_borrow()
            .ok()
            .and_then(|joining| joining.as_ref().map(|joining| joining.text().to_owned()))
            .unwrap_or_default()
    }

    /// Waits until the administrator has admitted this device and the space
    /// has arrived. Once only.
    pub fn joined(&self) -> Result<Promise, JsValue> {
        let joining = self
            .inner
            .try_borrow_mut()
            .ok()
            .and_then(|mut joining| joining.take())
            .ok_or_else(|| invalid("Joining.joined is called once."))?;
        Ok(promise(async move {
            Ok(Space::from(joining.joined().await.js()?).into())
        }))
    }
}

/// A new device's admission to its person through an exchange mailbox,
/// waiting for a device of the person to enter its text.
#[wasm_bindgen]
pub struct JoiningPerson {
    /// Taken by `joined()`.
    inner: RefCell<Option<frasil::JoiningPerson>>,
}

#[wasm_bindgen]
impl JoiningPerson {
    /// The text a device of the person enters in `Device.admitDevice`:
    /// show it as a QR code. Empty once `joined()` was called.
    #[wasm_bindgen(getter)]
    pub fn text(&self) -> String {
        self.inner
            .try_borrow()
            .ok()
            .and_then(|joining| joining.as_ref().map(|joining| joining.text().to_owned()))
            .unwrap_or_default()
    }

    /// Waits until this device is the person's and the person's spaces
    /// have arrived; resolves to them. Once only.
    pub fn joined(&self) -> Result<Promise, JsValue> {
        let joining = self
            .inner
            .try_borrow_mut()
            .ok()
            .and_then(|mut joining| joining.take())
            .ok_or_else(|| invalid("JoiningPerson.joined is called once."))?;
        Ok(promise(async move {
            let spaces = joining.joined().await.js()?;
            Ok(crate::convert::array(spaces, |space| {
                Space::from(space).into()
            }))
        }))
    }
}

/// A device's keys as `deviceKeys()` gives them, accepted only when they
/// hash to `member`, a device's ID (crypto.md, "Keys by their hash").
fn device_keys(keys: &JsValue, member: &frasil::MemberId) -> Result<DeviceKeys, JsValue> {
    let keys = bytes_in(keys).ok_or_else(|| invalid("the device keys are a Uint8Array."))?;
    public_keys::decode(&keys, &DeviceId(*member.as_bytes())).js()
}

/// One space's progress, with a structured FrasilError on failure.
fn admission_out(report: &frasil::SpaceAdmission) -> JsValue {
    Obj::new()
        .set("space", report.space.to_string())
        .set("granted", report.granted)
        .set(
            "error",
            report
                .result
                .as_ref()
                .err()
                .cloned()
                .map(crate::error::error)
                .unwrap_or(JsValue::UNDEFINED),
        )
        .build()
}
