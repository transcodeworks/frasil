//! Streaming blobs (adapter-blobs.md): a blob put from a reader and read
//! into a writer, with progress.
//!
//! An object's ID is keyed over its whole plaintext, so a put reads the
//! reader to its end before it seals; its progress counts the bytes read,
//! with no total until the end. The put then seals the object in memory,
//! as [`Blobs::put`] does: the plaintext, its sealed chunks and the stored
//! bytes are held together, so a put needs a few times the blob's size in
//! memory, and in a browser the WebAssembly memory bounds the blob. A read
//! of a blob the device does not hold whole fetches it first, as its
//! [`Read`] says, from the peers and members connected, reporting the share
//! fetched; it then opens the object chunk by chunk and writes each out as
//! it opens, so that a large blob never sits whole in memory: a get into a
//! writer, a range read and a content hash each hold a few chunks at a
//! time, and a range read the range too. A blob the application holds is
//! read from its file the same way.
//! Progress is `(bytes, total)`, and never goes back. A reference reads the
//! same way: a peer serves its object to this space, and the key it carries
//! opens it.
//!
//! Every check of units.md, 3.3 Reading an object still runs: the stored
//! bytes hash to the blob's locator (step 0) before any plaintext goes out,
//! each chunk opens before it is written (step 6), and a read of the whole
//! blob checks its plaintext's ID (step 7) before it writes the last chunk.
//! A get that fails part way has written a prefix of the blob: discard it.

use super::{BlobId, Blobs, Read};
use crate::error::{Error, Result};
use crate::objects::Plain;
use frasil_events::EventId;
use std::future::poll_fn;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The size of each read and write.
const PIECE: usize = 64 * 1024;

/// How long a get waits for the chunk stream to move before it gives up.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
const STALL: std::time::Duration = std::time::Duration::from_secs(30);

/// How many times an upload asks the connected peers.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
const TAKEN_ASKS: usize = 10;

/// How often a get looks at the chunk stream.
#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
const POLL: std::time::Duration = std::time::Duration::from_millis(100);

fn io(error: &std::io::Error) -> Error {
    Error::Connection(format!("the blob's stream: {error}"))
}

/// Progress that never goes back: each call reports a larger count.
pub(super) struct Reporter<F> {
    on_progress: F,
    reported: Option<u64>,
}

impl Reporter<fn(u64, Option<u64>)> {
    /// Progress nobody follows.
    pub(super) fn silent() -> Self {
        fn nobody(_: u64, _: Option<u64>) {}
        Self {
            on_progress: nobody,
            reported: None,
        }
    }
}

impl<F: FnMut(u64, Option<u64>)> Reporter<F> {
    /// Progress that `on_progress` follows.
    pub(super) fn following(on_progress: F) -> Self {
        Self {
            on_progress,
            reported: None,
        }
    }

    pub(super) fn report(&mut self, done: u64, total: Option<u64>) {
        if self.reported.is_none_or(|reported| done > reported) {
            self.reported = Some(done);
            (self.on_progress)(done, total);
        }
    }
}

async fn write_all(writer: &mut (impl AsyncWrite + Unpin), mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let written = poll_fn(|cx| Pin::new(&mut *writer).poll_write(cx, bytes))
            .await
            .map_err(|error| io(&error))?;
        if written == 0 {
            return Err(io(&std::io::ErrorKind::WriteZero.into()));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

impl Blobs {
    /// Puts a blob read from `reader` to its end, under `name` (none when
    /// empty). `on_progress(read, None)` follows the reading, then
    /// `on_progress(size, Some(size))` once the blob is kept.
    ///
    /// The reader is read in pieces, and the bytes are gathered whole
    /// before the object is sealed in memory: the blob is held whole, with
    /// its sealed form, until the put returns, since a reader read once
    /// cannot give the plaintext again for the second pass the object's ID
    /// needs. A source that can be read twice puts with a few chunks in
    /// memory: [`Blobs::put_seekable`], [`Blobs::put_file`] and
    /// [`Blobs::put_at`]. [`Blobs::put_from`] reads a file the
    /// application's provider holds without gathering its plaintext.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the reader fails; then as
    /// [`Blobs::put`].
    pub async fn put_stream(
        &self,
        name: &str,
        mut reader: impl AsyncRead + Unpin,
        on_progress: impl FnMut(u64, Option<u64>),
    ) -> Result<BlobId> {
        let mut progress = Reporter {
            on_progress,
            reported: None,
        };
        let mut bytes = Vec::new();
        let mut piece = vec![0u8; PIECE];
        loop {
            let mut buffer = ReadBuf::new(&mut piece);
            poll_fn(|cx| Pin::new(&mut reader).poll_read(cx, &mut buffer))
                .await
                .map_err(|error| io(&error))?;
            let read = buffer.filled().len();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&piece[..read]);
            progress.report(bytes.len() as u64, None);
        }
        let name = (!name.is_empty()).then_some(name);
        let id = self.put(name, &bytes).await?;
        let size = bytes.len() as u64;
        progress.reported = None;
        progress.report(size, Some(size));
        Ok(id)
    }

    /// Writes a blob's bytes into `writer`. A blob this device does not
    /// hold whole is fetched first, as `read` says ([`Read`]), from the
    /// connected peers, or from members over member connections.
    /// `on_progress(bytes, Some(size))` follows the fetch, then the
    /// writing.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] when the stream holds no blob of this ID;
    /// `Missing` while the device does not hold it and the read is
    /// [`local`](Read::local), or neither a peer nor a member of the space
    /// is connected, or the connected parties do not serve it for now;
    /// [`Error::Timeout`] when the fetch stops moving; `ObjectMismatch` or
    /// `Malformed` as [`Blobs::get`] says; [`Error::Connection`] when the
    /// writer fails; a class when the bytes do not open; as [`Blobs::get`]
    /// for what `read` asks.
    pub async fn get_stream(
        &self,
        id: BlobId,
        mut writer: impl AsyncWrite + Unpin,
        read: &Read,
        on_progress: impl FnMut(u64, Option<u64>),
    ) -> Result<()> {
        let mut progress = Reporter {
            on_progress,
            reported: None,
        };
        let entry = self.entry(id).await?;
        let size = entry.size;
        let reading = self
            .ready(&entry, read, &mut progress)
            .await?
            .ok_or(Error::Class("Missing"))?;
        let written = async {
            let mut written = 0u64;
            let mut chunks = self.plain(&entry, 0..u64::MAX).await?;
            while let Some((_, chunk)) = chunks.next().await? {
                for piece in chunk.chunks(PIECE) {
                    write_all(&mut writer, piece).await?;
                    written += piece.len() as u64;
                    progress.report(written, Some(size));
                }
            }
            poll_fn(|cx| Pin::new(&mut writer).poll_flush(cx))
                .await
                .map_err(|error| io(&error))
        }
        .await;
        reading.done().await?;
        written?;
        progress.report(size, Some(size));
        Ok(())
    }

    /// The SHA-256 of a blob's plaintext, a stable hash of its content for
    /// keying media or comparing with local files. A blob this device does
    /// not hold whole is fetched first, as `read` says; `None` when the
    /// blob is not here and cannot be fetched now, or cannot be opened
    /// yet, as for [`Blobs::get`]. The hash is computed on this device,
    /// chunk by chunk, and kept while the device is open and holds the
    /// blob; the protocol carries no such hash, and peers never see it.
    ///
    /// # Errors
    ///
    /// As [`Blobs::get`].
    pub async fn content_hash(&self, id: BlobId, read: &Read) -> Result<Option<[u8; 32]>> {
        let entry = self.entry(id).await?;
        let engine = self.space().device.engine();
        let space = self.space().id().event();
        let reading = match self.ready(&entry, read, &mut Reporter::silent()).await {
            Ok(Some(reading)) => reading,
            Ok(None) | Err(Error::Class("Missing")) => return Ok(None),
            Err(error) => return Err(error),
        };
        if let Some(hash) = engine.content_hash(&space, &entry.object) {
            reading.done().await?;
            return Ok(Some(hash));
        }
        let hashed = async {
            let mut hasher = frasil_crypto::primitives::Sha256Hasher::new();
            let mut chunks = self.plain(&entry, 0..u64::MAX).await?;
            while let Some((_, chunk)) = chunks.next().await? {
                hasher.update(&chunk);
            }
            Ok(hasher.finish())
        }
        .await;
        // Kept only while the device holds what was hashed: an object the
        // read drops takes its hash with it.
        if let Ok(hash) = &hashed {
            engine.keep_content_hash(space, entry.object, *hash);
        }
        reading.done().await?;
        match hashed {
            Ok(hash) => Ok(Some(hash)),
            Err(Error::Class("Missing" | "Sealed")) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// `len` bytes of a blob from byte `offset`, fewer at its end. A blob
    /// this device does not hold whole is fetched first, whole, as `read`
    /// says; `None` when the blob is not here and cannot be fetched now,
    /// as for [`Blobs::get`]. It holds a few chunks and the range, never
    /// the blob. Only the chunks that hold the range are opened once every
    /// check of units.md, 3.3 has run on the whole blob since the device
    /// opened or last fetched it: until then a range read runs them
    /// first, in one pass over the stored chunks that keeps only the
    /// range, so that the first range read of a blob reads all of it. A
    /// blob the application holds is read from its file, through to its
    /// end while the object ID is checked.
    ///
    /// # Errors
    ///
    /// As [`Blobs::get`].
    pub async fn get_range(
        &self,
        id: BlobId,
        offset: u64,
        len: u64,
        read: &Read,
    ) -> Result<Option<Vec<u8>>> {
        let entry = self.entry(id).await?;
        let end = offset.saturating_add(len).min(entry.size);
        if offset >= end {
            return Ok(Some(Vec::new()));
        }
        let reading = match self.ready(&entry, read, &mut Reporter::silent()).await {
            Ok(Some(reading)) => reading,
            Ok(None) | Err(Error::Class("Missing")) => return Ok(None),
            Err(error) => return Err(error),
        };
        let range = self.range_of(&entry, offset, end).await;
        reading.done().await?;
        range
    }

    /// The bytes of an entry from `offset` to `end`, from the chunks the
    /// device holds.
    async fn range_of(
        &self,
        entry: &frasil_adapter_blobs::Entry,
        offset: u64,
        end: u64,
    ) -> Result<Option<Vec<u8>>> {
        let chunk = frasil_units::limits::CHUNK_BYTES as u64;
        let chunks = offset / chunk..end.div_ceil(chunk);
        let mut plain = match self.plain(entry, chunks).await {
            Ok(plain) => plain,
            Err(Error::Class("Missing")) => return Ok(None),
            Err(error) => return Err(error),
        };
        let span = |from: u64, bytes: &[u8]| -> Vec<u8> {
            let start = offset.max(from) - from;
            let stop = end.min(from + bytes.len() as u64).saturating_sub(from);
            usize::try_from(start)
                .ok()
                .zip(usize::try_from(stop).ok())
                .filter(|(start, stop)| start < stop)
                .map_or_else(Vec::new, |(start, stop)| bytes[start..stop].to_vec())
        };
        let mut out = Vec::with_capacity(usize::try_from(end - offset).unwrap_or(0));
        loop {
            match plain.next().await {
                Ok(Some((index, bytes))) => out.extend(span(index * chunk, &bytes)),
                Ok(None) => break,
                Err(Error::Class("Missing")) => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Ok(Some(out))
    }

    /// The plaintext of a blob's object, chunk by chunk where the store
    /// holds it, for the chunks in `chunks`.
    async fn plain(
        &self,
        entry: &frasil_adapter_blobs::Entry,
        chunks: core::ops::Range<u64>,
    ) -> Result<Plain> {
        let reference = entry
            .reference
            .as_ref()
            .map(|reference| (EventId(reference.source), reference.object_key));
        self.space()
            .device
            .engine()
            .plain(&self.space().id().event(), &entry.object, reference, chunks)
            .await
    }

    /// Waits until the device holds a blob's object whole, as the
    /// connected peers' chunk streams bring it, or members' answers to the
    /// device's `ObjectWant` over member connections. A connection made
    /// while it waits serves the request too: the peers are looked at
    /// again at each turn, and one not seen before is asked.
    ///
    /// # Errors
    ///
    /// `Missing` when nothing is connected that could send the object, or
    /// when the space's connections ask for it no further for want of an
    /// answer ([`FetchEnd::Unserved`]); `ObjectMismatch` when what they
    /// were sent failed its checks ([`FetchEnd::Refused`]) and `Malformed`
    /// when it did not read as the object ([`FetchEnd::Malformed`]), each
    /// as soon as every connection of the space gave the request up;
    /// [`Error::Timeout`] when nothing arrives for [`STALL`], or the last
    /// connection goes.
    ///
    /// [`FetchEnd::Unserved`]: crate::fetch::FetchEnd::Unserved
    /// [`FetchEnd::Refused`]: crate::fetch::FetchEnd::Refused
    /// [`FetchEnd::Malformed`]: crate::fetch::FetchEnd::Malformed
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(super) async fn fetched<F: FnMut(u64, Option<u64>)>(
        &self,
        space: frasil_events::EventId,
        locator: frasil_adapter::Locator,
        size: u64,
        priority: crate::fetch::FetchPriority,
        progress: &mut Reporter<F>,
    ) -> Result<()> {
        use crate::fetch::FetchEnd;
        let device = &self.space().device;
        let engine = device.engine().clone();
        let connected = || {
            let peers: Vec<_> = device
                .peers_of(&space)
                .into_iter()
                .filter(|peer| !peer.handle().is_closed())
                .collect();
            // A connection that takes the space's requests could send it.
            let any = !peers.is_empty()
                || engine.member_attached(&space)
                || engine.fetches().taken(&space);
            (peers, any)
        };
        if !connected().1 {
            return Err(Error::Class("Missing"));
        }
        // Every chunk is wanted while this read waits: each connection of
        // the space fetches those the device lacks, and nothing of the
        // object is dropped meanwhile.
        let fetch = engine.fetch_chunks(space, locator, 0..u64::MAX, priority);
        let mut asked = Vec::new();
        let mut idle = std::time::Duration::ZERO;
        loop {
            if engine
                .read(&space, |replica| replica.holds_object(&locator))
                .await
                .unwrap_or(false)
            {
                return Ok(());
            }
            let (peers, any) = connected();
            for peer in &peers {
                let by = peer.handle().acknowledger();
                if !asked.contains(&by) {
                    asked.push(by);
                    peer.handle().fetch(space);
                }
            }
            let members = engine.object_progress(&space, &locator).await;
            let fetched = peers
                .iter()
                .filter_map(|peer| peer.handle().status().fetching.get(&locator).copied())
                .chain(members)
                .filter_map(|(got, total)| {
                    let total = total.filter(|&total| total > 0)?;
                    let share = u128::from(size) * u128::from(got.min(total)) / u128::from(total);
                    u64::try_from(share).ok()
                })
                .max();
            match fetched {
                Some(done) if progress.reported.is_none_or(|reported| done > reported) => {
                    progress.report(done, Some(size));
                    idle = std::time::Duration::ZERO;
                }
                _ => idle += POLL,
            }
            if idle >= STALL || !any {
                return Err(Error::Timeout);
            }
            // The request's end is heard as it is told, between two looks.
            tokio::select! {
                end = fetch.ended() => {
                    return Err(Error::Class(match end {
                        FetchEnd::Refused => "ObjectMismatch",
                        FetchEnd::Malformed => "Malformed",
                        FetchEnd::Unserved => "Missing",
                    }));
                }
                () = device.sleep(POLL) => {}
            }
        }
    }

    /// How much of an object the connected peers and members have sent,
    /// by share of its `size`: `None` while none is sending it.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(super) async fn fetch_progress(
        &self,
        locator: frasil_adapter::Locator,
        size: u64,
    ) -> Option<u64> {
        let device = &self.space().device;
        let space = self.space().id().event();
        let members = device.engine().object_progress(&space, &locator).await;
        device
            .peers_of(&space)
            .into_iter()
            .filter(|peer| !peer.handle().is_closed())
            .filter_map(|peer| peer.handle().status().fetching.get(&locator).copied())
            .chain(members)
            .map(|(got, total)| match total.filter(|&total| total > 0) {
                Some(total) => {
                    let share = u128::from(size) * u128::from(got.min(total)) / u128::from(total);
                    u64::try_from(share).unwrap_or(size)
                }
                None => 0,
            })
            .max()
    }

    /// Without a connection, nothing sends an object.
    #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
    #[allow(clippy::unused_async)]
    pub(super) async fn fetch_progress(
        &self,
        _locator: frasil_adapter::Locator,
        _size: u64,
    ) -> Option<u64> {
        None
    }

    /// Hands an object no unit names yet to the connected peers, and
    /// returns once one of them holds it whole, by its own answer. A member
    /// takes no object before a unit names it (units.md, "Sync", objects),
    /// so members are not asked.
    ///
    /// `Missing` when no peer takes it: none is connected, each refused, or
    /// none answered in time. `Changed` when a held file changed, so that
    /// the object can no longer be sealed from it.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(super) async fn taken(
        &self,
        space: frasil_events::EventId,
        locator: frasil_adapter::Locator,
    ) -> Result<()> {
        let device = &self.space().device;
        let mut waited = std::time::Duration::ZERO;
        // Only an object the device held when the put began can change: on
        // a device that keeps no objects, its absence says nothing, and
        // every ask is made before the put is `Missing`.
        let held = self.stored(&space, &locator).await;
        // A connection takes a moment to hold its store right, so a peer
        // that answers no is asked again, for a moment.
        for _ in 0..TAKEN_ASKS {
            let peers: Vec<_> = device
                .peers_of(&space)
                .into_iter()
                .filter(|peer| !peer.handle().is_closed())
                .collect();
            if peers.is_empty() {
                break;
            }
            let mut answers: Vec<_> = peers
                .iter()
                .map(|peer| peer.handle().upload(space, locator))
                .collect();
            while !answers.is_empty() && waited < STALL {
                let mut open = Vec::new();
                for mut answer in answers {
                    use tokio::sync::oneshot::error::TryRecvError;
                    match answer.try_recv() {
                        Ok(true) => return Ok(()),
                        Ok(false) | Err(TryRecvError::Closed) => {}
                        Err(TryRecvError::Empty) => open.push(answer),
                    }
                }
                answers = open;
                if !answers.is_empty() {
                    device.sleep(POLL).await;
                    waited += POLL;
                }
            }
            if held && !self.stored(&space, &locator).await {
                return Err(Error::Class("Changed"));
            }
            device.sleep(POLL).await;
        }
        Err(Error::Class("Missing"))
    }

    /// Without a connection, no peer takes an object.
    #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
    #[allow(clippy::unused_async)]
    pub(super) async fn taken(
        &self,
        _space: frasil_events::EventId,
        _locator: frasil_adapter::Locator,
    ) -> Result<()> {
        Err(Error::Class("Missing"))
    }

    /// Whether the device can give an object's bytes, by its first chunk
    /// alone, as an upload starts: never the whole object. Under `held`, a
    /// file found changed is withdrawn, and its object is no longer stored.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    async fn stored(
        &self,
        space: &frasil_events::EventId,
        locator: &frasil_adapter::Locator,
    ) -> bool {
        self.space()
            .device
            .engine()
            .object_upload(space, locator)
            .await
            .is_some()
    }

    /// Without a connection, a blob the device does not hold is missing.
    #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
    #[allow(clippy::unused_async)]
    pub(super) async fn fetched<F: FnMut(u64, Option<u64>)>(
        &self,
        _space: frasil_events::EventId,
        _locator: frasil_adapter::Locator,
        _size: u64,
        _priority: crate::fetch::FetchPriority,
        _progress: &mut Reporter<F>,
    ) -> Result<()> {
        Err(Error::Class("Missing"))
    }

    /// Whether a peer or a member of the space is connected, so that a
    /// read could fetch a blob now.
    #[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
    pub(super) fn can_fetch(&self) -> bool {
        let device = &self.space().device;
        let space = self.space().id().event();
        device
            .peers_of(&space)
            .into_iter()
            .any(|peer| !peer.handle().is_closed())
            || device.engine().member_attached(&space)
    }

    /// Without a connection, nothing can be fetched.
    #[cfg(not(any(feature = "server", feature = "iroh", feature = "server-socket")))]
    pub(super) fn can_fetch(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Reporter;

    #[test]
    fn progress_never_goes_back() {
        let mut seen = Vec::new();
        {
            let mut progress = Reporter {
                on_progress: |done, total| seen.push((done, total)),
                reported: None,
            };
            progress.report(5, Some(10));
            progress.report(3, Some(10));
            progress.report(10, Some(10));
        }
        assert_eq!(seen, vec![(5, Some(10)), (10, Some(10))]);
    }

    /// A read hears how the request for its blob ended as soon as the
    /// space's connections give it up, and fails with what fits: it does
    /// not wait until the fetch is found not to move.
    #[cfg(all(
        feature = "adapter-blobs",
        any(feature = "server", feature = "iroh", feature = "server-socket")
    ))]
    #[tokio::test]
    async fn a_read_ends_as_the_request_for_its_blob_ends() {
        use crate::fetch::FetchEnd;
        use crate::{Device, Error, Read, Storage};
        use std::time::Duration;

        let device = Device::open(Storage::Memory, &[1; 32]).await.unwrap();
        let space = device.create_space().await.unwrap();
        let blobs = space.create_blobs().unwrap();
        let id = blobs.put(None, &[7; 1000]).await.unwrap();
        let locator = blobs.entry(id).await.unwrap().object;
        // Absent here, by the application's choice.
        blobs.drop_local(id).await.unwrap();
        let engine = device.engine().clone();
        let of = space.id().event();

        for end in [FetchEnd::Refused, FetchEnd::Malformed, FetchEnd::Unserved] {
            // A connection that takes the space's requests, and gives
            // this one up once the read has made it.
            let taker = engine.fetches().attach(of);
            let reading = {
                let blobs = blobs.clone();
                tokio::spawn(async move { blobs.get(id, &Read::new()).await })
            };
            let gives_up = async {
                while engine.fetches().of(&of).is_empty() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                match end {
                    FetchEnd::Unserved => taker.unserved(&locator),
                    end => taker.give_up(&locator, end),
                }
            };
            tokio::time::timeout(Duration::from_secs(5), gives_up)
                .await
                .expect("the read asks for the blob");
            let read = tokio::time::timeout(Duration::from_secs(5), reading)
                .await
                .expect("the read ends with its request")
                .unwrap();
            match end {
                FetchEnd::Refused => {
                    assert!(
                        matches!(read, Err(Error::Class("ObjectMismatch"))),
                        "{read:?}"
                    );
                }
                FetchEnd::Malformed => {
                    assert!(matches!(read, Err(Error::Class("Malformed"))), "{read:?}");
                }
                // Not served for now: not here, and a later read asks
                // again.
                FetchEnd::Unserved => assert!(matches!(read, Ok(None)), "{read:?}"),
            }
            drop(taker);
            assert!(engine.fetches().of(&of).is_empty());
        }
    }
}
