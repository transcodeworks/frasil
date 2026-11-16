//! A space, as a JavaScript class: `frasil::Space`, its members and its
//! streams.

use crate::callback::confirm;
use crate::convert::{Obj, array, bytes, id};
use crate::error::{Js, invalid};
use crate::promise;
use crate::streams::{Blobs, Document, Records};
use frasil::{HistoryMode, Level, MemberKind, StreamId, StreamKind};
use js_sys::{Function, Promise};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use wasm_bindgen::prelude::*;

/// A space this device holds.
#[wasm_bindgen]
pub struct Space {
    pub(crate) inner: frasil::Space,
}

impl From<frasil::Space> for Space {
    fn from(inner: frasil::Space) -> Self {
        Self { inner }
    }
}

impl Space {
    pub(crate) fn inner(&self) -> &frasil::Space {
        &self.inner
    }
}

/// A level by its name.
pub(crate) fn level(name: &str) -> Result<Level, JsValue> {
    Level::from_name(name)
        .ok_or_else(|| invalid("the level is \"read\", \"write\" or \"administer\"."))
}

/// A history mode by its name; `from-now-on` when `undefined`.
fn history(name: Option<String>) -> Result<HistoryMode, JsValue> {
    match name.as_deref() {
        None | Some("from-now-on") => Ok(HistoryMode::FromNowOn),
        Some("with-history") => Ok(HistoryMode::WithHistory),
        Some(_) => Err(invalid("history is \"with-history\" or \"from-now-on\".")),
    }
}

fn claimant(name: Option<String>) -> Result<frasil::Claimant, JsValue> {
    match name.as_deref() {
        None | Some("device") => Ok(frasil::Claimant::Device),
        Some("person") => Ok(frasil::Claimant::Person),
        Some(_) => Err(invalid("claimant is \"device\" or \"person\".")),
    }
}

fn member_kind(kind: MemberKind) -> &'static str {
    match kind {
        MemberKind::Device => "device",
        MemberKind::Person => "person",
        MemberKind::Space => "space",
        _ => "other",
    }
}

fn stream_kind(kind: &StreamKind) -> String {
    match kind {
        StreamKind::Document => "document".into(),
        StreamKind::Records => "records".into(),
        StreamKind::Blobs => "blobs".into(),
        StreamKind::Other(adapter_type) => adapter_type.clone(),
        _ => "other".into(),
    }
}

#[wasm_bindgen]
impl Space {
    /// The space's ID: 64 hex digits.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id().to_string()
    }

    /// A 32-byte key for the application's own data of this space, one per
    /// `purpose`, which goes with the space (at-rest.md, "Application
    /// keys").
    #[wasm_bindgen(js_name = deriveKey)]
    pub fn derive_key(&self, purpose: String) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            let key = space.derive_key(&purpose).await.js()?;
            Ok(js_sys::Uint8Array::from(&key[..]).into())
        })
    }

    /// The kind of space the application made it; `undefined` for a space
    /// created without one.
    pub fn kind(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            Ok(space
                .kind()
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, |kind| JsValue::from_str(&kind)))
        })
    }

    /// Whether this device keeps nothing of the space at rest
    /// (ext-guests.md, "Nothing at rest"): resolves to a boolean.
    #[wasm_bindgen(js_name = keepsNothingAtRest)]
    pub fn keeps_nothing_at_rest(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move { Ok(JsValue::from_bool(space.keeps_nothing_at_rest().await)) })
    }

    /// This device's level in the space (`"read"`, `"write"` or
    /// `"administer"`); `undefined` once it is no member.
    pub fn level(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            Ok(space
                .level()
                .await
                .map_or(JsValue::UNDEFINED, |level| JsValue::from_str(level.name())))
        })
    }

    /// The space's members, as this device's view has them: `{ id, kind,
    /// level, name, rank, dormant }`, `name` `undefined` when it was
    /// admitted with none, `rank` `undefined` but for an administrator.
    pub fn members(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            let members = space.members().await.js()?;
            Ok(array(members, |member| {
                Obj::new()
                    .set("id", member.id.to_string())
                    .set("kind", member_kind(member.kind))
                    .set("level", member.level.name())
                    .set(
                        "name",
                        member.name.map_or(JsValue::UNDEFINED, JsValue::from),
                    )
                    .set(
                        "rank",
                        member.rank.map_or(JsValue::UNDEFINED, JsValue::from),
                    )
                    .build()
            }))
        })
    }

    /// Removes a member by its ID. The space rotates its keys.
    pub fn remove(&self, member: String) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.remove(member).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// The space's checkpoints as this device holds them (roster.md, 3.15
    /// Checkpoints): `{ inEffect, epoch, pending, following, bad, late,
    /// mixed, rosterEventsSince, frameBytesSince, forgot, refused, checking,
    /// withheld, rivals, backdated }`. Each pending checkpoint is `{ id,
    /// epoch, proposedBy, waitingFor }`, each backdated one `{ checkpoint,
    /// proposedBy, removal }`; `inEffect` and `following` are `null` with
    /// none.
    pub fn checkpoints(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            Ok(crate::checkpoints::status_out(
                &space.checkpoints().await.js()?,
            ))
        })
    }

    /// Proposes a checkpoint of the space now, whatever the device's
    /// checkpoint policy (roster.md, 3.15.7 Clients, "Proposing"). Resolves
    /// to the checkpoint's ID.
    #[wasm_bindgen(js_name = proposeCheckpoint)]
    pub fn propose_checkpoint(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            let id = space.propose_checkpoint().await.js()?;
            Ok(JsValue::from(id.to_string()))
        })
    }

    /// This device's membership changes that a checkpoint made late and that
    /// it does not make again by itself (roster.md, 3.15.7, "Work concurrent
    /// with a checkpoint"): `{ event, member, kind, level }`, `kind`
    /// `"grant"`, `"change"`, `"remove"` or `"other"`.
    #[wasm_bindgen(js_name = lateChanges)]
    pub fn late_changes(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            Ok(crate::checkpoints::late_changes_out(
                &space.late_changes().await.js()?,
            ))
        })
    }

    /// The space's streams this device holds a change of: `{ id, kind }`,
    /// `kind` `"document"`, `"records"`, `"blobs"`, or another adapter's
    /// type.
    pub fn streams(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            let streams = space.streams().await.js()?;
            Ok(array(streams, |stream| {
                Obj::new()
                    .set("id", stream.id.to_string())
                    .set("kind", stream_kind(&stream.kind))
                    .build()
            }))
        })
    }

    /// Every version tagged in the space.
    pub fn versions(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            Ok(crate::convert::array(
                &space.versions().await.js()?,
                crate::streams::version_out,
            ))
        })
    }

    /// Removes a tag.
    pub fn untag(&self, version: String) -> Result<Promise, JsValue> {
        let id: frasil::VersionId = version
            .parse()
            .map_err(|_| crate::error::invalid("a version's ID is 32 hex digits"))?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.untag(id).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// The space's versions stream, a Records stream of Frasil's own:
    /// leave it to Frasil.
    #[wasm_bindgen(getter, js_name = versionsStream)]
    pub fn versions_stream(&self) -> String {
        self.inner.versions_stream().to_string()
    }

    /// The count of authored events awaiting the acknowledgement used by flush.
    #[wasm_bindgen(js_name = pendingAuthoredChanges)]
    pub fn pending_authored_changes(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move { Ok(JsValue::from(space.pending_authored_changes().await)) })
    }

    /// Whether every change this device made in the space is durable.
    #[wasm_bindgen(js_name = isDurable)]
    pub fn is_durable(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move { Ok(JsValue::from_bool(space.is_durable().await)) })
    }

    /// Sends every change this device made in the space that is not yet
    /// durable, and resolves once a peer holds them; rejects when they are
    /// not durable within 30 seconds.
    pub fn flush(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.flush().await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Resolves as soon as every change this device made in the space is
    /// durable; rejects when it is not within `within_ms` milliseconds. It
    /// does not wait for an administration connection to finish.
    #[wasm_bindgen(js_name = waitDurable)]
    pub fn wait_durable(&self, within_ms: u32) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space
                .wait_durable(std::time::Duration::from_millis(u64::from(within_ms)))
                .await
                .js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Whether this device may write in the space as far as a restore
    /// goes: `false` only while a device opened as restored has not synced
    /// the space (at-rest.md, 3.6 "After a restore").
    #[wasm_bindgen(js_name = isWriteReady)]
    pub fn is_write_ready(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move { Ok(JsValue::from_bool(space.is_write_ready().await)) })
    }

    /// Resolves once this device may write in the space, at once when it
    /// already may; rejects with `sync_before_writing` when it has not
    /// synced the space within `within_ms` milliseconds.
    #[wasm_bindgen(js_name = waitWriteReady)]
    pub fn wait_write_ready(&self, within_ms: f64) -> Promise {
        let space = self.inner.clone();
        let within = crate::reads::wait(within_ms);
        promise(async move {
            space.wait_write_ready(within).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Pauses the space's sync with always-on peers, as for a suspended
    /// library: no store and no fetch until `resumeSync`. The space stays
    /// readable and writable on this device.
    #[wasm_bindgen(js_name = pauseSync)]
    pub fn pause_sync(&self) {
        self.inner.pause_sync();
    }

    /// Resumes the space's sync with always-on peers: it catches up.
    #[wasm_bindgen(js_name = resumeSync)]
    pub fn resume_sync(&self) {
        self.inner.resume_sync();
    }

    /// Whether the space's sync with always-on peers is paused.
    #[wasm_bindgen(js_name = isSyncPaused)]
    pub fn is_sync_paused(&self) -> bool {
        self.inner.is_sync_paused()
    }

    /// Ends a session: every guest of it, by its 16 bytes, is removed in
    /// one change of the membership.
    #[wasm_bindgen(js_name = endSession)]
    pub fn end_session(&self, session: Vec<u8>) -> Result<Promise, JsValue> {
        let session: [u8; 16] = session
            .try_into()
            .map_err(|_| crate::error::invalid("the session is a Uint8Array of 16 bytes."))?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.end_session(session).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// [`admit`](Self::admit), admitting the newcomer as an administrator
    /// at `rank`, 0 to 255, at most this device's own; `admit` refuses
    /// `"administer"`, which has no default rank.
    #[wasm_bindgen(js_name = admitAdministrator)]
    pub fn admit_administrator(
        &self,
        code: String,
        rank: u8,
        name: String,
        confirm_with: Function,
        history_name: Option<String>,
    ) -> Result<Promise, JsValue> {
        let history = history(history_name)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space
                .admit_administrator(&code, rank, history, &name, move |code, newcomer| {
                    confirm(confirm_with, code, newcomer)
                })
                .await
                .js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Admits the device whose `Joining.text` a newcomer shows, at `level`,
    /// through the exchange mailbox at the peer that text names.
    /// `confirm(code, newcomerName)` is called with the six-digit code both
    /// screens show and returns `true`, or a promise of `true`, when the
    /// person saw it on both. `name` is what the newcomer's screen shows for this
    /// device. `history` is `"from-now-on"` (the default) or
    /// `"with-history"`.
    pub fn admit(
        &self,
        code: String,
        level_name: String,
        name: String,
        confirm_with: Function,
        history_name: Option<String>,
    ) -> Result<Promise, JsValue> {
        let level = level(&level_name)?;
        let history = history(history_name)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space
                .admit_with(&code, level, history, &name, move |code, newcomer| {
                    confirm(confirm_with, code, newcomer)
                })
                .await
                .js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Makes an invite link into the space at `level` (`"read"` or
    /// `"write"`), open for `lifetime` seconds, 15 minutes to 7 days
    /// (ext-invite-links.md). `history` is `"from-now-on"` (the default) or
    /// `"with-history"`. `claimant` is `"device"` (the default), or
    /// `"person"`: the link then admits the person of the device that opens
    /// it, with every device on its list. Resolves to the link.
    #[wasm_bindgen(js_name = inviteLink)]
    pub fn invite_link(
        &self,
        level_name: String,
        lifetime: f64,
        history_name: Option<String>,
        claimant_name: Option<String>,
    ) -> Result<Promise, JsValue> {
        let level = level(&level_name)?;
        let history = history(history_name)?;
        let claimant = claimant(claimant_name)?;
        if !crate::space_file::link_lifetime(lifetime) {
            return Err(invalid(
                "the lifetime is a number of seconds, 15 minutes to 7 days.",
            ));
        }
        let lifetime = Duration::from_secs_f64(lifetime);
        let space = self.inner.clone();
        Ok(promise(async move {
            let link = space
                .invite_link_for(claimant, level, lifetime, history)
                .await
                .js()?;
            Ok(JsValue::from_str(&link))
        }))
    }

    /// Revokes an invite link into the space that nobody has claimed yet:
    /// a claim of it is refused from then on.
    #[wasm_bindgen(js_name = revokeInviteLink)]
    pub fn revoke_invite_link(&self, link: String) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.revoke_invite_link(&link).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Whether this device writes here only suggestions: its grant carries
    /// `suggest`.
    #[wasm_bindgen(js_name = canSuggest)]
    pub fn can_suggest(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move { Ok(JsValue::from_bool(space.can_suggest().await)) })
    }

    /// Creates a restricted space under this one (ext-restricted-spaces.md).
    #[wasm_bindgen(js_name = createRestricted)]
    pub fn create_restricted(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move { Ok(Space::from(space.create_restricted().await.js()?).into()) })
    }

    /// Grants a person, all their devices, at `level`.
    #[wasm_bindgen(js_name = grantPerson)]
    pub fn grant_person(&self, person: String, level_name: String) -> Result<Promise, JsValue> {
        let person = id::<frasil::PersonId>(&person)?;
        let level = level(&level_name)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.grant_person(person, level).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Changes a member's level.
    #[wasm_bindgen(js_name = setLevel)]
    pub fn set_level(&self, member: String, level_name: String) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let level = level(&level_name)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.set_level(member, level).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Raises a device member to `"administer"` at `rank`, 0 to 255, at
    /// most this device's own: a larger rank outranks a smaller one.
    pub fn raise(&self, member: String, rank: u8) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.raise(member, rank).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Changes an administrator's rank: a lowering to `"write"`, then a
    /// raise at `rank`.
    #[wasm_bindgen(js_name = setRank)]
    pub fn set_rank(&self, member: String, rank: u8) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.set_rank(member, rank).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Makes a device member the space's recovery member: an administrator
    /// at the top rank marked dormant. Only a device at the top rank makes
    /// one.
    #[wasm_bindgen(js_name = makeRecoveryMember)]
    pub fn make_recovery_member(&self, member: String) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.make_recovery_member(member).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Marks an administrator dormant, or no longer: a checkpoint does not
    /// wait for a dormant administrator.
    #[wasm_bindgen(js_name = setDormant)]
    pub fn set_dormant(&self, member: String, dormant: bool) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.set_dormant(member, dormant).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// The space's recovery members' IDs.
    #[wasm_bindgen(js_name = recoveryMembers)]
    pub fn recovery_members(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            let members = space.recovery_members().await.js()?;
            Ok(array(members, |member| JsValue::from(member.to_string())))
        })
    }

    /// A member's rank while it administers, else `undefined`.
    pub fn rank(&self, member: String) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            Ok(space
                .rank(member)
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, JsValue::from))
        }))
    }

    /// This device's rank while it administers, else `undefined`.
    #[wasm_bindgen(js_name = myRank)]
    pub fn my_rank(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            Ok(space
                .my_rank()
                .await
                .js()?
                .map_or(JsValue::UNDEFINED, JsValue::from))
        })
    }

    /// Makes a member a suggester, or no longer one.
    #[wasm_bindgen(js_name = setSuggester)]
    pub fn set_suggester(&self, member: String, suggester: bool) -> Result<Promise, JsValue> {
        let member = id::<frasil::MemberId>(&member)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            space.set_suggester(member, suggester).await.js()?;
            Ok(JsValue::UNDEFINED)
        }))
    }

    /// Erases the whole space at its peers.
    pub fn erase(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.erase().await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Leaves the space, then forgets it on this device.
    pub fn leave(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.leave().await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Forgets the space on this device; the roster does not change.
    pub fn forget(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.forget().await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// The space's ephemeral channel (ext-ephemeral.md).
    pub fn ephemeral(&self) -> Ephemeral {
        Ephemeral {
            inner: self.inner.ephemeral(),
        }
    }

    /// Attaches the space to a library by a ticket from its issuer
    /// (ext-libraries.md): a create or an import ticket before a peer hosts
    /// the space, a move ticket after.
    #[wasm_bindgen(js_name = attachLibrary)]
    pub fn attach_library(&self, ticket: Vec<u8>) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.attach_library(&ticket).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// Keeps the home peer of the space's library, the origin's URL its
    /// issuer returned beside the ticket (ext-libraries.md, "The home
    /// peer"): named first in welcomes, tried first when a peer answers
    /// `moved`, and synced with now when no open connection syncs the
    /// space.
    #[wasm_bindgen(js_name = setHomePeer)]
    pub fn set_home_peer(&self, url: String) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            space.set_home_peer(&url).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// The peers the device knows for the space, as origins' URLs, home
    /// peer first.
    #[wasm_bindgen(js_name = knownPeers)]
    pub fn known_peers(&self) -> Promise {
        let space = self.inner.clone();
        promise(async move {
            let peers = space.known_peers().await.js()?;
            Ok(array(&peers, |url| JsValue::from(url.as_str())))
        })
    }

    /// Creates a Loro document. It exists in the space from its first edit.
    #[wasm_bindgen(js_name = createDocument)]
    pub fn create_document(&self) -> Result<Document, JsValue> {
        self.inner.create_document().js().map(Document::from)
    }

    /// A Loro document of the space.
    pub fn document(&self, stream: String) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            Ok(Document::from(space.document(stream).await.js()?).into())
        }))
    }

    /// Creates a set of Records tables. It exists in the space from its
    /// first write.
    #[wasm_bindgen(js_name = createRecords)]
    pub fn create_records(&self) -> Result<Records, JsValue> {
        self.inner.create_records().js().map(Records::from)
    }

    /// Records tables of the space.
    pub fn records(&self, stream: String) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            Ok(Records::from(space.records(stream).await.js()?).into())
        }))
    }

    /// Creates a blob stream. It exists in the space from its first blob.
    #[wasm_bindgen(js_name = createBlobs)]
    pub fn create_blobs(&self) -> Result<Blobs, JsValue> {
        self.inner.create_blobs().js().map(Blobs::from)
    }

    /// A blob stream of the space.
    pub fn blobs(&self, stream: String) -> Result<Promise, JsValue> {
        let stream = id::<StreamId>(&stream)?;
        let space = self.inner.clone();
        Ok(promise(async move {
            Ok(Blobs::from(space.blobs(stream).await.js()?).into())
        }))
    }
}

/// A space's ephemeral channel (ext-ephemeral.md): messages to the members
/// connected now, kept nowhere.
#[wasm_bindgen]
pub struct Ephemeral {
    inner: frasil::Ephemeral,
}

#[wasm_bindgen]
impl Ephemeral {
    /// Sends a message to the members connected now. It may be lost.
    pub fn send(&self, message: Vec<u8>) -> Promise {
        let ephemeral = self.inner.clone();
        promise(async move {
            ephemeral.send(&message).await.js()?;
            Ok(JsValue::UNDEFINED)
        })
    }

    /// The messages other members send, from now on.
    pub fn subscribe(&self) -> EphemeralStream {
        EphemeralStream {
            inner: Rc::new(RefCell::new(Some(self.inner.subscribe()))),
        }
    }
}

/// The messages of an ephemeral channel, from the moment they were asked
/// for.
#[wasm_bindgen]
pub struct EphemeralStream {
    /// Lent to the one `next()` in flight, and given back when it settles.
    inner: Rc<RefCell<Option<frasil::EphemeralStream>>>,
}

#[wasm_bindgen]
impl EphemeralStream {
    /// The next message, `{ from, data }`: its sender's device and its
    /// bytes; `undefined` once the device is gone. One call at a time.
    pub fn next(&self) -> Result<Promise, JsValue> {
        let slot = self.inner.clone();
        let mut stream = slot
            .try_borrow_mut()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| invalid("EphemeralStream.next is already waiting."))?;
        Ok(promise(async move {
            let message = stream.next().await;
            if let Ok(mut back) = slot.try_borrow_mut() {
                *back = Some(stream);
            }
            Ok(message.map_or(JsValue::UNDEFINED, |(from, data)| {
                Obj::new()
                    .set("from", from.to_string())
                    .set("data", bytes(&data))
                    .build()
            }))
        }))
    }
}
