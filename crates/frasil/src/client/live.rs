//! Live editing of a Loro document: an application keeps its own
//! `LoroDoc`, commits its local updates, and imports the others' as they
//! arrive.
//!
//! A [`Live`] handle holds one incarnation of this device in the document
//! (adapter-loro.md, section 3.1, "Writing") for as long as it lives: the
//! application sets its `LoroDoc`'s peer ID to [`Live::peer_id`], and each
//! commit writes the operations of that peer that the document does not
//! hold yet as one unit, with counters that follow on.

use super::streams::Document;
use crate::documents::loro_state;
use crate::error::{Error, Result};
use frasil_adapter_loro::write::export_unit;
use frasil_adapter_loro::{Counter, Incarnation};
use loro::{ExportMode, LoroDoc, VersionVector};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use tokio::sync::{broadcast, watch};

/// A live handle on a Loro document, from [`Document::live`]. Clones share
/// its incarnation.
///
/// The application keeps a document of its own and hands each commit to
/// [`Live::commit`]. A native application edits Frasil's own document
/// instead through [`Document::lend`] (decision: one document); `Live`
/// stays for the browser package, whose Loro document cannot share the
/// engine's, and for applications that keep their own.
#[derive(Debug, Clone)]
pub struct Live {
    shared: Arc<Shared>,
}

/// What a live handle and its change feeds share.
struct Shared {
    document: Document,
    incarnation: Incarnation,
    /// The document as this handle knows it: the replica's state, with the
    /// application's commits imported, kept current in the background.
    mirror: Mutex<LoroDoc>,
    /// Rises each time the mirror takes others' operations; closed once
    /// the device is gone.
    bumps: watch::Receiver<u64>,
    /// How many operations of this handle's peer the application gave to
    /// [`Live::commit`]. A suggestion's peer can equal it (a suggestion's
    /// incarnation is its own `seq`), and once accepted those operations
    /// are others' news to the application, not its own.
    committed: Mutex<i32>,
}

impl core::fmt::Debug for Shared {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Live")
            .field("document", &self.document.id())
            .field("peer", &self.incarnation.peer())
            .finish_non_exhaustive()
    }
}

impl Shared {
    fn mirror(&self) -> std::sync::MutexGuard<'_, LoroDoc> {
        self.mirror.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn adapter(error: impl core::fmt::Display) -> Error {
    Error::Adapter(error.to_string())
}

impl Document {
    /// Opens the document for live editing: a handle that holds one
    /// incarnation of this device, and a copy of the document kept current
    /// as changes arrive. A native application that can edit Frasil's own
    /// document uses [`Document::lend`].
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`]; [`Error::NotAllowed`] when no incarnation
    /// is free.
    pub async fn live(&self) -> Result<Live> {
        let engine = self.space.device.engine().clone();
        let space = self.space.id().event();
        let notices = engine.subscribe();
        let (incarnation, doc) = engine.begin_live(space, &self.opening).await?;
        let (tell, bumps) = watch::channel(0);
        let shared = Arc::new(Shared {
            document: self.clone(),
            incarnation,
            mirror: Mutex::new(doc),
            bumps,
            committed: Mutex::new(0),
        });
        self.space
            .device
            .spawn(Box::pin(follow(Arc::downgrade(&shared), notices, tell)));
        Ok(Live { shared })
    }
}

/// Keeps a live handle's mirror current: on each change in its space, it
/// imports what the replica's document holds beyond the mirror. It ends
/// once every handle and feed is dropped, or the device is gone.
async fn follow(
    shared: Weak<Shared>,
    mut notices: broadcast::Receiver<crate::device::Notice>,
    tell: watch::Sender<u64>,
) {
    let (engine, space, stream) = match shared.upgrade() {
        Some(shared) => (
            shared.document.space.device.engine().clone(),
            shared.document.space.id().event(),
            shared.document.opening.stream(),
        ),
        None => return,
    };
    loop {
        match notices.recv().await {
            Ok(notice) if notice.space != space => continue,
            Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return,
        }
        let Some(live) = shared.upgrade() else {
            return;
        };
        let update = engine
            .read(&space, |replica| {
                let state = loro_state(replica, &stream)?;
                let held = live.mirror().oplog_vv();
                let newer = state
                    .doc()
                    .oplog_vv()
                    .iter()
                    .any(|(peer, end)| held.get(peer).copied().unwrap_or(0) < *end);
                if !newer {
                    return None;
                }
                state.doc().export(ExportMode::updates(&held)).ok()
            })
            .await;
        if let Ok(Some(update)) = update
            && live.mirror().import(&update).is_ok()
        {
            tell.send_modify(|bumps| *bumps = bumps.wrapping_add(1));
        }
    }
}

impl Live {
    /// The peer ID of this handle's incarnation. The application sets it
    /// as its own `LoroDoc`'s peer (`LoroDoc::set_peer_id`) before it
    /// edits, and edits under no other.
    pub fn peer_id(&self) -> u64 {
        self.shared.incarnation.peer()
    }

    /// Commits a Loro update the application made under
    /// [`peer_id`](Self::peer_id): every operation of that peer the
    /// document does not hold yet is written as one unit, or as many, one
    /// after another, as step 4 of adapter-loro.md's checks needs, signed
    /// and sealed by this device. Nothing is written when there is none.
    ///
    /// # Errors
    ///
    /// [`Error::Adapter`] when Loro does not read `update`;
    /// [`Error::NotAllowed`] unless this device writes in the space;
    /// [`Error::SyncBeforeWriting`]; [`Error::RotationDue`].
    pub async fn commit(&self, update: &[u8]) -> Result<()> {
        let shared = &self.shared;
        {
            let mirror = shared.mirror();
            let before = mirror.oplog_vv().get(&shared.incarnation.peer()).copied();
            let committed = *shared
                .committed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if before.unwrap_or(0) > committed {
                return Err(Error::Adapter(
                    "the document holds an accepted suggestion under this handle's peer; open the document live again".into(),
                ));
            }
            mirror.import(update).map_err(adapter)?;
            let after = mirror
                .oplog_vv()
                .get(&shared.incarnation.peer())
                .copied()
                .unwrap_or(0);
            *shared
                .committed
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = after;
        }
        let document = &shared.document;
        let stream = document.opening.stream();
        let incarnation = shared.incarnation;
        let peer = incarnation.peer();
        // As many units as step 4 of the checks needs (adapter-loro.md,
        // section 3.1), one after another, each from where the last ended.
        let mut written: Counter = 0;
        loop {
            let mut nothing = false;
            let unit = document
                .space
                .device
                .engine()
                .write_unit(
                    document.space.id().event(),
                    &document.opening,
                    |replica, _| {
                        let from = loro_state(replica, &stream)
                            .and_then(|state| state.doc().oplog_vv().get(&peer).copied())
                            .unwrap_or(0)
                            .max(written);
                        match export_unit(&shared.mirror(), peer, from).map_err(adapter)? {
                            Some((blob, span)) => {
                                written = span.end;
                                Ok(frasil_adapter_loro::Content::edit(
                                    incarnation.incarnation,
                                    blob,
                                )
                                .encode())
                            }
                            None => {
                                nothing = true;
                                Err(Error::Adapter("the update holds no new operation".into()))
                            }
                        }
                    },
                )
                .await;
            match unit {
                Err(_) if nothing => return Ok(()),
                Err(error) => return Err(error),
                Ok(_) => {}
            }
        }
    }

    /// The document's operations beyond `version`, an encoded Loro
    /// `VersionVector` (`VersionVector::encode`), as one Loro update; all
    /// of them, as a snapshot, when `version` is empty.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when `version` does not decode; [`Error::Adapter`]
    /// when Loro fails to export.
    pub fn export_since(&self, version: &[u8]) -> Result<Vec<u8>> {
        let mirror = self.shared.mirror();
        if version.is_empty() {
            return mirror.export(ExportMode::Snapshot).map_err(adapter);
        }
        let version = VersionVector::decode(version)
            .map_err(|_| Error::Invalid("the version is not an encoded Loro version vector"))?;
        mirror
            .export(ExportMode::updates(&version))
            .map_err(adapter)
    }

    /// The version this handle holds, an encoded Loro `VersionVector`.
    pub fn version(&self) -> Vec<u8> {
        self.shared.mirror().oplog_vv().encode()
    }

    /// The changes others make from now on, as Loro updates to import.
    pub fn changes(&self) -> Changes {
        let mut bumps = self.shared.bumps.clone();
        bumps.mark_unchanged();
        Changes {
            seen: self.shared.mirror().oplog_vv(),
            shared: self.shared.clone(),
            bumps,
        }
    }

    /// Suggests a change (adapter-loro.md, section 3.4): `update`, Loro's
    /// bytes for operations over the document's current state, made on a
    /// fork of it, never imported into the application's own document.
    /// It is written again under the suggestion's own peer, and enters the
    /// document only once accepted ([`Document::accept`]).
    ///
    /// # Errors
    ///
    /// [`Error::Adapter`] when Loro does not read `update`, or it changes
    /// nothing; [`Error::NotAllowed`] unless this device writes or suggests
    /// in the space; [`Error::SyncBeforeWriting`]; [`Error::RotationDue`].
    pub async fn suggest(&self, update: &[u8]) -> Result<()> {
        self.shared.document.suggest(update).await.map(drop)
    }
}

/// The changes others make to a live document, from [`Live::changes`].
#[derive(Debug)]
pub struct Changes {
    shared: Arc<Shared>,
    bumps: watch::Receiver<u64>,
    seen: VersionVector,
}

impl Changes {
    /// The next Loro update of others' operations, which the application
    /// imports into its `LoroDoc`; `None` once the device is gone.
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        let peer = self.shared.incarnation.peer();
        loop {
            {
                let mirror = self.shared.mirror();
                let held = mirror.oplog_vv();
                // The application holds the operations it committed.
                let mut from = self.seen.clone();
                let committed = *self
                    .shared
                    .committed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                if committed > from.get(&peer).copied().unwrap_or(0) {
                    from.insert(peer, committed);
                }
                let newer = held
                    .iter()
                    .any(|(id, end)| from.get(id).copied().unwrap_or(0) < *end);
                if newer && let Ok(update) = mirror.export(ExportMode::updates(&from)) {
                    self.seen = held;
                    return Some(update);
                }
            }
            if self.bumps.changed().await.is_err() {
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Device, Options, Storage};
    use loro::{ExportMode, LoroDoc};

    #[tokio::test]
    async fn a_live_handle_commits_under_one_peer_and_suggests() {
        let options = Options::new().never_restored();
        let device = Device::open_with(Storage::Memory, &[1; 32], options)
            .await
            .unwrap();
        let space = device.create_space().await.unwrap();
        let document = space.create_document().unwrap();
        let live = document.live().await.unwrap();
        let app = LoroDoc::new();
        app.set_peer_id(live.peer_id()).unwrap();
        for word in ["Hello", " world"] {
            let before = app.oplog_vv();
            let text = app.get_text("body");
            text.insert(text.len_unicode(), word).unwrap();
            app.commit();
            let update = app.export(ExportMode::updates(&before)).unwrap();
            live.commit(&update).await.unwrap();
        }
        assert_eq!(document.text("body").await.unwrap(), "Hello world");
        assert_ne!(document.live().await.unwrap().peer_id(), live.peer_id());

        let fork = LoroDoc::new();
        fork.import(&live.export_since(&[]).unwrap()).unwrap();
        let before = fork.oplog_vv();
        fork.get_text("body").insert(0, "> ").unwrap();
        fork.commit();
        live.suggest(&fork.export(ExportMode::updates(&before)).unwrap())
            .await
            .unwrap();
        let open = document.suggestions().await.unwrap();
        assert_eq!(open.len(), 1);
        document.accept(&[open[0].id]).await.unwrap();
        assert_eq!(document.text("body").await.unwrap(), "> Hello world");
        assert!(document.suggestions().await.unwrap().is_empty());
    }
}
