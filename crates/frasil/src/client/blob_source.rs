//! Blobs put from a source that can be read twice (adapter-blobs.md;
//! units.md, 2.8 Objects): a file, a seekable reader, or anything that
//! reads at an offset.
//!
//! An object's ID is keyed over its whole plaintext and every chunk names
//! it, so the put reads the source once for the ID and again to seal it,
//! a chunk at a time, committing a few chunks to the store at once. It
//! holds a few chunks in memory, whatever the blob's size, and the blob's
//! stored bytes and locator are those of [`Blobs::put`] for the same
//! bytes. The source must not change while it is put: a source that does
//! fails `Changed`, and nothing is kept.

use super::{BlobId, Blobs};
use crate::error::{Error, Result};
use crate::held::ObjectReader;
use frasil_store::BoxFuture;
use frasil_store::store::MaybeSend;
use std::future::poll_fn;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncSeek, ReadBuf};

fn io(error: &std::io::Error) -> Error {
    Error::Connection(format!("the blob's source: {error}"))
}

/// Progress that never goes back.
struct Forward<F> {
    on_progress: F,
    reported: Option<u64>,
}

impl<F: FnMut(u64, Option<u64>)> Forward<F> {
    fn report(&mut self, done: u64, total: u64) {
        if self.reported.is_none_or(|reported| done > reported) {
            self.reported = Some(done);
            (self.on_progress)(done, Some(total));
        }
    }
}

impl Blobs {
    /// Puts a blob read from `reader`, under `name` (none when empty),
    /// without holding it whole: the reader is read to its end for the
    /// blob's ID, then again from the start to seal it a chunk at a time.
    /// `on_progress(bytes, Some(size))` follows the second reading, and
    /// ends at `(size, Some(size))` once the blob is kept.
    ///
    /// Under the space's `held` policy the bytes go through the
    /// application's provider, a piece at a time, as [`Blobs::put`]'s do.
    ///
    /// # Errors
    ///
    /// `Changed` when the source changed while it was read; the reader's;
    /// then as [`Blobs::put`].
    pub async fn put_at(
        &self,
        name: &str,
        reader: &mut dyn ObjectReader,
        on_progress: impl FnMut(u64, Option<u64>) + MaybeSend,
    ) -> Result<BlobId> {
        let engine = self.space().device.engine();
        let handle = engine.platform().nonce::<16>()?;
        let name = (!name.is_empty()).then_some(name);
        let mut progress = Forward {
            on_progress,
            reported: None,
        };
        let (_, _, size) = engine
            .put_blob_from(
                self.space().id().event(),
                self.opening(),
                handle,
                name,
                reader,
                &mut |done, total| progress.report(done, total),
            )
            .await?;
        progress.report(size, size);
        Ok(BlobId::from_bytes(handle))
    }

    /// [`Blobs::put_at`] from a reader that can seek, such as a file:
    /// it is read to its end, then sought back to its start and read
    /// again.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the reader fails; then as
    /// [`Blobs::put_at`].
    pub async fn put_seekable(
        &self,
        name: &str,
        reader: impl AsyncRead + AsyncSeek + Unpin + MaybeSend,
        on_progress: impl FnMut(u64, Option<u64>) + MaybeSend,
    ) -> Result<BlobId> {
        let mut reader = SeekReader {
            reader,
            position: None,
        };
        self.put_at(name, &mut reader, on_progress).await
    }

    /// [`Blobs::put_at`] from the file at `path`. The file is read with
    /// the platform's blocking reads, one piece at a time.
    ///
    /// # Errors
    ///
    /// [`Error::Connection`] when the file does not open or a read fails;
    /// then as [`Blobs::put_at`].
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn put_file(
        &self,
        name: &str,
        path: impl AsRef<std::path::Path>,
        on_progress: impl FnMut(u64, Option<u64>) + MaybeSend,
    ) -> Result<BlobId> {
        let file = std::fs::File::open(path).map_err(|error| io(&error))?;
        self.put_at(name, &mut FileReader(file), on_progress).await
    }
}

/// An [`ObjectReader`] over a reader that can seek.
struct SeekReader<R> {
    reader: R,
    /// Where the reader stands, once known.
    position: Option<u64>,
}

impl<R: AsyncRead + AsyncSeek + Unpin + MaybeSend> ObjectReader for SeekReader<R> {
    fn read_at<'a>(&'a mut self, offset: u64, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            if self.position != Some(offset) {
                self.position = None;
                Pin::new(&mut self.reader)
                    .start_seek(std::io::SeekFrom::Start(offset))
                    .map_err(|error| io(&error))?;
                let at = poll_fn(|cx| Pin::new(&mut self.reader).poll_complete(cx))
                    .await
                    .map_err(|error| io(&error))?;
                if at != offset {
                    return Ok(0);
                }
            }
            let mut buffer = ReadBuf::new(buf);
            poll_fn(|cx| Pin::new(&mut self.reader).poll_read(cx, &mut buffer))
                .await
                .map_err(|error| io(&error))?;
            let read = buffer.filled().len();
            self.position = Some(offset + read as u64);
            Ok(read)
        })
    }
}

/// An [`ObjectReader`] over a file, with blocking reads.
#[cfg(not(target_arch = "wasm32"))]
struct FileReader(std::fs::File);

#[cfg(not(target_arch = "wasm32"))]
impl ObjectReader for FileReader {
    fn read_at<'a>(&'a mut self, offset: u64, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        use std::io::{Read, Seek, SeekFrom};
        Box::pin(async move {
            self.0
                .seek(SeekFrom::Start(offset))
                .map_err(|error| io(&error))?;
            loop {
                match self.0.read(buf) {
                    Ok(read) => return Ok(read),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(io(&error)),
                }
            }
        })
    }
}
