//! Objects sealed from a source read twice (units.md, 2.8 Objects), with a
//! few chunks in memory at a time.
//!
//! The object ID is keyed over the whole plaintext and every chunk's
//! associated data names it, so a put reads its source twice: pass one for
//! the ID and the size, pass two to seal each chunk in order. Pass two
//! commits the sealed chunks to the store a few at a time, without the
//! device's lock, and hashes the plaintext again: a source that changed
//! between the passes, or while pass two read it, fails `Changed`. The
//! stored bytes and the locator are those of a put of the same plaintext
//! from memory.
//!
//! The chunks of pass two are written under the object ID before the
//! digest is known, and the store keeps an object's parts by ID. So that a
//! source that changed cannot write over an object the replica already
//! holds parts of, pass two then seals without keeping anything: if the
//! replica holds that object whole at the locator found, the put is done;
//! otherwise a third pass keeps the chunks.

use crate::at_rest::{Batch, ObjectWriter as StoreWriter};
use crate::device::Engine;
use crate::error::{Error, Result};
use crate::held::{ObjectReader, read_exact};
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_store::store::MaybeSend;
use frasil_units::objects::{ObjectIdPass, ObjectKeys, ObjectSealer};

/// How many bytes a read of pass one asks for.
const READ_BYTES: usize = 64 * 1024;

/// The sealed bytes a put from a source commits at once: a few chunks,
/// which bound what it holds in memory.
const COMMIT_BYTES: usize = 4 << 20;

/// The object a put from a source sealed.
#[derive(Debug)]
#[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
pub(crate) struct Sourced {
    /// The locator.
    pub locator: Locator,
    /// The key reference its header names.
    pub reference: Vec<u8>,
    /// The plaintext's length.
    pub size: u64,
    /// The parts to commit with a unit that names the object: a small
    /// object's, when asked for; otherwise empty, the parts being kept.
    pub parts: Vec<ObjectPart>,
}

/// Pass one over a source: the object ID and the plaintext's length. With
/// `expected`, the source is read to that length and must end there;
/// otherwise it is read until a read gives nothing. `progress` hears the
/// bytes read.
///
/// # Errors
///
/// `Changed` when the source is shorter or longer than `expected`;
/// `TooLarge` past 2^40 bytes; the reader's.
pub(crate) async fn id_pass(
    reader: &mut dyn ObjectReader,
    keys: &ObjectKeys,
    expected: Option<u64>,
    progress: &mut (impl FnMut(u64) + MaybeSend),
) -> Result<([u8; 32], u64)> {
    let mut pass = ObjectIdPass::new(keys);
    let mut buffer = vec![0; READ_BYTES];
    loop {
        let offset = pass.size();
        let want = match expected {
            Some(size) => {
                usize::try_from(size - offset).map_or(READ_BYTES, |left| left.min(READ_BYTES))
            }
            None => READ_BYTES,
        };
        if want == 0 {
            break;
        }
        let read = reader.read_at(offset, &mut buffer[..want]).await?;
        if read == 0 {
            if expected.is_some() {
                return Err(Error::Class("Changed"));
            }
            break;
        }
        pass.update(&buffer[..read.min(want)])
            .map_err(Error::class)?;
        progress(pass.size());
    }
    if let Some(size) = expected
        && reader.read_at(size, &mut [0u8; 1]).await? != 0
    {
        return Err(Error::Class("Changed"));
    }
    Ok(pass.finish())
}

/// Where pass two's chunks go.
enum Sink {
    /// Hashed and let go.
    Discard,
    /// Held, to commit with a unit or in memory.
    Collect(Vec<ObjectPart>),
    /// Committed to the store a few at a time.
    Store(Box<Stored>),
}

/// Chunks being committed to the store.
struct Stored {
    writer: StoreWriter,
    pending: Vec<ObjectPart>,
    bytes: usize,
    /// The addresses committed, to forget should the put fail.
    addresses: Vec<Vec<u8>>,
}

impl Sink {
    async fn take(&mut self, part: ObjectPart) -> Result<()> {
        match self {
            Self::Discard => Ok(()),
            Self::Collect(parts) => {
                parts.push(part);
                Ok(())
            }
            Self::Store(stored) => {
                stored.bytes += part.chunk.len();
                stored.pending.push(part);
                if stored.bytes >= COMMIT_BYTES {
                    stored.flush().await?;
                }
                Ok(())
            }
        }
    }
}

impl Stored {
    async fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let parts: Vec<&ObjectPart> = self.pending.iter().collect();
        let sealed = self.writer.seal(&parts)?;
        self.addresses
            .extend(sealed.iter().map(|(address, _)| address.clone()));
        self.pending.clear();
        self.bytes = 0;
        self.writer.commit(sealed).await
    }
}

/// A locator with the object ID and a digest not yet known: the store
/// keeps parts by ID.
fn unfinished(id: &[u8; 32]) -> Locator {
    let mut locator = [0; 64];
    locator[..32].copy_from_slice(id);
    locator
}

/// Pass two: each chunk sealed in order and given to `sink`; then the
/// source must end at the size pass one found. `progress` hears the
/// plaintext bytes sealed.
async fn seal_pass(
    reader: &mut dyn ObjectReader,
    sealer: &mut ObjectSealer,
    sink: &mut Sink,
    progress: &mut (impl FnMut(u64) + MaybeSend),
) -> Result<()> {
    let placeholder = unfinished(&sealer.object_id());
    while let Some((start, length)) = sealer.next_range() {
        let length = usize::try_from(length).map_err(|_| Error::Class("TooLarge"))?;
        let plain = zeroize::Zeroizing::new(read_exact(reader, start, length).await?);
        let index = sealer.next_index();
        let sealed = sealer.seal_next(&plain).map_err(Error::class)?;
        sink.take(ObjectPart {
            locator: placeholder,
            header: (index == 0).then(|| sealer.header().to_vec()),
            index,
            chunk: sealed.sealed,
        })
        .await?;
        progress(start + length as u64);
    }
    if reader.read_at(sealer.size(), &mut [0u8; 1]).await? != 0 {
        return Err(Error::Class("Changed"));
    }
    Ok(())
}

/// A sealer's verdict on the plaintext of pass two: `Changed` for one with
/// another ID than pass one's.
fn changed(error: Error) -> Error {
    match error {
        Error::Class("ObjectMismatch") => Error::Class("Changed"),
        other => other,
    }
}

impl Engine {
    /// Seals an object from a source under the space's current state and
    /// keeps it (units.md, "Objects"), reading the source twice and holding
    /// a few chunks at a time. The locator and the stored bytes are those
    /// of [`Engine::put_object`] for the same plaintext. Returns the
    /// locator and the plaintext's length.
    ///
    /// # Errors
    ///
    /// `Changed` when the source changed between the passes or while it
    /// was read; [`Error::UnknownSpace`]; [`Error::NotAllowed`] while the
    /// device holds no current state; `TooLarge`; the reader's and the
    /// store's.
    pub async fn put_object_from(
        &self,
        space: EventId,
        reader: &mut dyn ObjectReader,
    ) -> Result<(Locator, u64)> {
        let put = self.seal_from(space, reader, false, &mut |_, _| {}).await?;
        Ok((put.locator, put.size))
    }

    /// Seals an object from a source, outside the device's lock, and keeps
    /// it. With `in_unit`, a small object's parts are handed back to commit
    /// with the unit that names it, as a put from memory does. `progress`
    /// hears `(sealed, size)` as pass two goes.
    pub(crate) async fn seal_from(
        &self,
        space: EventId,
        reader: &mut dyn ObjectReader,
        in_unit: bool,
        progress: &mut (impl FnMut(u64, u64) + MaybeSend),
    ) -> Result<Sourced> {
        let (reference, key) = {
            let state = self.lock().await;
            self.sealing(&state, &space)?
        };
        let keys = ObjectKeys::of(&key);
        let (id, size) = id_pass(reader, &keys, None, &mut |_| {}).await?;
        let new_sealer =
            || ObjectSealer::new(&space, &key, &reference, id, size).map_err(Error::class);
        let mut sealer = new_sealer()?;
        let stored_length = 4 + sealer.header().len() as u64 + size + 40 * sealer.count();
        #[cfg(feature = "adapter-blobs")]
        let small = in_unit && stored_length < crate::objects::OWN_COMMIT_BYTES as u64;
        #[cfg(not(feature = "adapter-blobs"))]
        let small = {
            let _ = (in_unit, stored_length);
            false
        };
        let mut report = |sealed: u64| progress(sealed, size);

        // Pass two dry when the replica holds parts of an object of this
        // ID: the module's doc says why.
        let known = {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            replica.knows_object_id(&id) || state.held.entry(&space, &id).is_some()
        };
        let mut checked = None;
        if known {
            seal_pass(reader, &mut sealer, &mut Sink::Discard, &mut report).await?;
            let locator = sealer
                .finish()
                .map_err(|e| changed(Error::class(e)))?
                .locator;
            let whole = {
                let state = self.lock().await;
                let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
                replica.is_located(&locator) && replica.stored_parts(&locator).is_some()
            };
            if whole {
                return Ok(Sourced {
                    locator,
                    reference,
                    size,
                    parts: Vec::new(),
                });
            }
            checked = Some(locator);
            sealer = new_sealer()?;
        }

        let header = sealer.header().to_vec();
        let mut sink = if small {
            Sink::Collect(Vec::new())
        } else {
            self.store_sink(&space).await?
        };
        let pass = seal_pass(reader, &mut sealer, &mut sink, &mut report).await;
        let pass = match pass {
            Ok(()) => sealer.finish().map_err(|e| changed(Error::class(e))),
            Err(error) => Err(error),
        };
        let pass = match pass {
            Ok(sealed) if checked.is_some_and(|locator| locator != sealed.locator) => {
                Err(Error::Class("Changed"))
            }
            Ok(sealed) => Ok(sealed.locator),
            Err(error) => Err(error),
        };
        let locator = match pass {
            Ok(locator) => locator,
            Err(error) => {
                if let Sink::Store(stored) = sink {
                    self.forget_stored(&space, &id, *stored).await;
                }
                return Err(error);
            }
        };
        let parts = match sink {
            Sink::Discard => Vec::new(),
            Sink::Collect(parts) => {
                let parts: Vec<ObjectPart> = parts
                    .into_iter()
                    .map(|part| ObjectPart { locator, ..part })
                    .collect();
                if small {
                    parts
                } else {
                    // A log kept in memory alone: its parts are kept there.
                    self.store_parts(space, &parts.iter().collect::<Vec<_>>(), true)
                        .await?;
                    Vec::new()
                }
            }
            Sink::Store(mut stored) => {
                if let Err(error) = stored.flush().await {
                    self.forget_stored(&space, &id, *stored).await;
                    return Err(error);
                }
                self.note_stored(space, locator, header, *stored).await?;
                Vec::new()
            }
        };
        Ok(Sourced {
            locator,
            reference,
            size,
            parts,
        })
    }

    /// Where pass two's chunks go: the store, through a writer that needs
    /// no hold on the device; or memory, for a log kept in memory alone.
    async fn store_sink(&self, space: &EventId) -> Result<Sink> {
        let mut state = self.lock().await;
        if !state.replicas.contains_key(space) {
            return Err(Error::UnknownSpace);
        }
        if state.vault.is_memory_only(&space.0) {
            return Ok(Sink::Collect(Vec::new()));
        }
        if !state.vault.has_log(&space.0) {
            let mut batch = Batch::default();
            state
                .vault
                .add_log(&mut batch, &space.0, frasil_store::tables::LogKind::Space)?;
            state.vault.commit(batch).await?;
        }
        Ok(match state.vault.object_writer(&space.0) {
            Some(writer) => Sink::Store(Box::new(Stored {
                writer,
                pending: Vec::new(),
                bytes: 0,
                addresses: Vec::new(),
            })),
            None => Sink::Collect(Vec::new()),
        })
    }

    /// Notes an object whose parts pass two committed: the store holds
    /// its header and every chunk, and its bytes hash to its locator, since
    /// this device sealed them.
    async fn note_stored(
        &self,
        space: EventId,
        locator: Locator,
        header: Vec<u8>,
        stored: Stored,
    ) -> Result<()> {
        let count = frasil_units::objects::Header::read(&header)
            .map(|read| {
                frasil_units::objects::chunk_count(
                    read.size,
                    frasil_units::limits::CHUNK_BYTES as u64,
                )
            })
            .map_err(Error::class)?;
        let mut state = self.lock().await;
        if !stored.writer.is_current(&state.vault) {
            // The log was forgotten or kept in memory meanwhile: what was
            // written is no one's.
            let _ = stored.writer.forget(stored.addresses).await;
            return Ok(());
        }
        // The store holds the chunks, so the parts noted carry none.
        let parts: Vec<ObjectPart> = (0..count)
            .map(|index| ObjectPart {
                locator,
                header: (index == 0).then(|| header.clone()),
                index,
                chunk: Vec::new(),
            })
            .collect();
        Self::note_parts(&mut state, space, &parts.iter().collect::<Vec<_>>(), true).await
    }

    /// After a failed pass two: forgets what it committed, unless the
    /// replica came to hold parts of that object meanwhile.
    async fn forget_stored(&self, space: &EventId, id: &[u8; 32], stored: Stored) {
        let known = {
            let state = self.lock().await;
            state
                .replicas
                .get(space)
                .is_some_and(|replica| replica.knows_object_id(id))
        };
        if !known && !stored.addresses.is_empty() {
            let _ = stored.writer.forget(stored.addresses).await;
        }
    }
}

#[cfg(feature = "adapter-blobs")]
impl Engine {
    /// [`Engine::put_blob_under`] from a source read twice rather than
    /// from memory: under `held`, the source is copied through the
    /// provider's writer and the file it made is put (at-rest.md, "Held
    /// objects"); otherwise the object is sealed from the source a few
    /// chunks at a time ([`Engine::put_object_from`]). `progress` hears
    /// `(bytes, size)` as the copy or the sealing goes. Returns the unit,
    /// the locator and the plaintext's length.
    ///
    /// # Errors
    ///
    /// As [`Engine::put_object_from`] and [`Engine::write_unit`].
    pub async fn put_blob_from(
        &self,
        space: EventId,
        stream: &frasil_units::stream::Opening,
        handle: [u8; 16],
        name: Option<&str>,
        reader: &mut dyn ObjectReader,
        progress: &mut (impl FnMut(u64, u64) + MaybeSend),
    ) -> Result<(EventId, Locator, u64)> {
        use frasil_adapter_blobs::content::Op;
        use frasil_adapter_blobs::entry::Entry;
        let (locator, key, size, stored) =
            match self.put_created_from(space, reader, progress).await? {
                Some((locator, key, size)) => (locator, key, size, Vec::new()),
                None => {
                    let put = self.seal_from(space, reader, true, progress).await?;
                    (put.locator, put.reference, put.size, put.parts)
                }
            };
        let entry = Entry {
            object: locator,
            key,
            size,
            media_type: None,
            name: name.map(str::to_owned),
            reference: None,
        };
        let id = self
            .write_blob_op(
                space,
                stream,
                Op::put(handle, entry),
                vec![locator],
                &[],
                stored,
            )
            .await?;
        Ok((id, locator, size))
    }

    /// [`Engine::put_created`] from a source: under `held`, the source is
    /// copied through the provider's writer a piece at a time, and the
    /// file it made is put. Returns `None` under `sealed`.
    async fn put_created_from(
        &self,
        space: EventId,
        reader: &mut dyn ObjectReader,
        progress: &mut (impl FnMut(u64, u64) + MaybeSend),
    ) -> Result<Option<(Locator, Vec<u8>, u64)>> {
        let (provider, key) = {
            let mut state = self.lock().await;
            self.refresh_held(&mut state);
            let Some(provider) = self.provider_of(&state, &space) else {
                return Ok(None);
            };
            let (_, key) = self.sealing(&state, &space)?;
            (provider, key)
        };
        let (id, size) = id_pass(reader, &ObjectKeys::of(&key), None, &mut |_| {}).await?;
        let mut writer = provider
            .create(crate::client::SpaceId::of(space), id, size, &[])
            .await?;
        let mut copy = async || -> Result<()> {
            let mut offset = 0;
            while offset < size {
                let length = usize::try_from(size - offset)
                    .map_or(READ_BYTES * 16, |left| left.min(READ_BYTES * 16));
                let piece = zeroize::Zeroizing::new(read_exact(reader, offset, length).await?);
                writer.write(&piece).await?;
                offset += length as u64;
                progress(offset, size);
            }
            if reader.read_at(size, &mut [0u8; 1]).await? != 0 {
                return Err(Error::Class("Changed"));
            }
            Ok(())
        };
        if let Err(error) = copy().await {
            let _ = writer.abort().await;
            return Err(error);
        }
        let (token, _) = writer.finish().await?;
        match self.put_held(space, &token).await {
            Ok((locator, key)) => {
                let size = self
                    .held_record(&space, &locator)
                    .await
                    .map_or(size, |record| record.size);
                Ok(Some((locator, key, size)))
            }
            Err(error) => {
                let _ = provider.forget(&token).await;
                Err(error)
            }
        }
    }
}
