//! An object uploaded to a peer a chunk at a time (units.md, 3.14 Sync,
//! objects; transport.md, "Objects over HTTP"), read from where the device
//! keeps it: the store's sealed chunks, or the plaintext the application
//! holds, sealed again (at-rest.md, "Held objects").
//!
//! [`ObjectUpload`] gives the object's parts in order, reading one chunk at
//! a time. [`UploadSlices`] cuts the stored bytes, `u32be(len(header)) ||
//! header || chunk_0 || …`, into the HTTP routes' slices as the chunks
//! come, holding less than a slice and a chunk.

use crate::device::Engine;
use crate::error::{Error, Result};
use crate::snapshots::ObjectPart;
use frasil_adapter::Locator;
use frasil_events::EventId;
use frasil_units::limits::{CHUNK_BYTES, NONCE_BYTES, TAG_BYTES};
use frasil_units::objects::{Header, chunk_count, plain_length};

/// An object's parts, read one chunk at a time to upload.
pub(crate) struct ObjectUpload {
    engine: Engine,
    space: EventId,
    locator: Locator,
    header: Vec<u8>,
    size: u64,
    count: u64,
    next: u64,
    /// Chunk 0, read to learn the header.
    first: Option<ObjectPart>,
}

impl Engine {
    /// An upload of an object this device holds whole, sealed or held:
    /// `None` when it holds no copy it can give.
    pub(crate) async fn object_upload(
        &self,
        space: &EventId,
        locator: &Locator,
    ) -> Option<ObjectUpload> {
        let first = self.upload_part(space, locator, 0).await.ok()??;
        let header = first.header.clone()?;
        let read = Header::read(&header).ok()?;
        if read.object_id[..] != locator[..32] {
            return None;
        }
        Some(ObjectUpload {
            engine: self.clone(),
            space: *space,
            locator: *locator,
            count: chunk_count(read.size, CHUNK_BYTES as u64),
            size: read.size,
            header,
            next: 0,
            first: Some(first),
        })
    }

    /// Chunk `index` of an object, as [`serve_parts`](Self::serve_parts)
    /// or, for a held object, [`serve_held`](Self::serve_held) gives it.
    async fn upload_part(
        &self,
        space: &EventId,
        locator: &Locator,
        index: u64,
    ) -> Result<Option<ObjectPart>> {
        let parts = match self.serve_parts(space, locator, index, 1).await? {
            Some(parts) if !parts.is_empty() => parts,
            _ => match self.serve_held(*space, locator, index, 1).await? {
                Some(parts) => parts,
                None => return Ok(None),
            },
        };
        Ok(parts.into_iter().find(|part| part.index == index))
    }
}

impl ObjectUpload {
    /// The object's header.
    #[cfg(any(feature = "server", feature = "server-socket"))]
    pub(crate) fn header(&self) -> &[u8] {
        &self.header
    }

    /// The next part, chunk 0 with the header; `None` once every chunk
    /// was given.
    ///
    /// # Errors
    ///
    /// `Missing` when the device no longer holds the chunk, or it is not
    /// the length the header gives it; the store's and the provider's.
    pub(crate) async fn next_part(&mut self) -> Result<Option<ObjectPart>> {
        if self.next >= self.count {
            return Ok(None);
        }
        let part = match self.first.take() {
            Some(part) => part,
            None => self
                .engine
                .upload_part(&self.space, &self.locator, self.next)
                .await?
                .ok_or(Error::Class("Missing"))?,
        };
        let length = plain_length(self.size, CHUNK_BYTES as u64, self.next)
            + (NONCE_BYTES + TAG_BYTES) as u64;
        if part.index != self.next || part.chunk.len() as u64 != length {
            return Err(Error::Class("Missing"));
        }
        self.next += 1;
        Ok(Some(ObjectPart {
            locator: self.locator,
            header: (part.index == 0).then(|| self.header.clone()),
            ..part
        }))
    }
}

/// Cuts stored bytes, given in pieces, into slices of a fixed length:
/// every slice that length but the last.
#[cfg(any(feature = "server", feature = "server-socket", test))]
#[derive(Debug)]
pub(crate) struct Slicer {
    slice: usize,
    /// The bytes given and not yet cut: less than a slice and a piece.
    pending: Vec<u8>,
    index: u64,
}

#[cfg(any(feature = "server", feature = "server-socket", test))]
impl Slicer {
    /// Slices of `slice` bytes, starting with `u32be(len(header)) ||
    /// header`.
    ///
    /// # Errors
    ///
    /// `Malformed` for a slice length of 0; `TooLarge` for a header whose
    /// length does not fit four bytes.
    pub(crate) fn new(header: &[u8], slice: usize) -> Result<Self> {
        if slice == 0 {
            return Err(Error::Class("Malformed"));
        }
        let length = u32::try_from(header.len()).map_err(|_| Error::Class("TooLarge"))?;
        let mut pending = length.to_be_bytes().to_vec();
        pending.extend_from_slice(header);
        Ok(Self {
            slice,
            pending,
            index: 0,
        })
    }

    /// Whether a whole slice is ready.
    pub(crate) fn is_ready(&self) -> bool {
        self.pending.len() >= self.slice
    }

    /// Takes the next piece of the stored bytes.
    pub(crate) fn push(&mut self, piece: &[u8]) {
        self.pending.extend_from_slice(piece);
    }

    /// The next slice and its index: a whole one, or with `last`, what is
    /// left; `None` when there is none.
    pub(crate) fn take(&mut self, last: bool) -> Option<(u64, Vec<u8>)> {
        if self.pending.is_empty() || (!last && !self.is_ready()) {
            return None;
        }
        let rest = self.pending.split_off(self.pending.len().min(self.slice));
        let slice = std::mem::replace(&mut self.pending, rest);
        let index = self.index;
        self.index += 1;
        Some((index, slice))
    }
}

/// An object's stored bytes, cut into slices of a fixed length as its
/// chunks are read: every slice that length but the last.
#[cfg(any(feature = "server", feature = "server-socket"))]
pub(crate) struct UploadSlices {
    upload: ObjectUpload,
    slicer: Slicer,
    ended: bool,
}

#[cfg(any(feature = "server", feature = "server-socket"))]
impl UploadSlices {
    /// Slices of `slice` bytes, which must not be 0.
    pub(crate) fn new(upload: ObjectUpload, slice: usize) -> Result<Self> {
        let slicer = Slicer::new(upload.header(), slice)?;
        Ok(Self {
            upload,
            slicer,
            ended: false,
        })
    }

    /// The next slice and its index; `None` after the last.
    ///
    /// # Errors
    ///
    /// As [`ObjectUpload::next_part`].
    pub(crate) async fn next(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        while !self.ended && !self.slicer.is_ready() {
            match self.upload.next_part().await? {
                Some(part) => self.slicer.push(&part.chunk),
                None => self.ended = true,
            }
        }
        Ok(self.slicer.take(self.ended))
    }
}

#[cfg(test)]
mod tests {
    use super::Slicer;
    use crate::objects::{SLICE_BYTES, SliceReader};
    use frasil_events::EventId;
    use frasil_keys::RotationSet;
    use frasil_units::limits::CHUNK_BYTES;
    use frasil_units::objects::seal_object;

    /// Cut a chunk at a time, the slices are the stored bytes' fixed-length
    /// pieces, and a fetch's reader cuts them back into the sealed chunks:
    /// for one chunk, an exact number, and a remainder.
    #[test]
    fn slices_cut_as_chunks_come_are_the_stored_bytes_slices() {
        let reference = RotationSet::single(EventId([3; 32])).encode();
        for size in [
            0,
            10,
            CHUNK_BYTES,
            2 * CHUNK_BYTES,
            3 * CHUNK_BYTES + CHUNK_BYTES / 2,
        ] {
            let plain: Vec<u8> = (0..size).map(|i| (i % 253) as u8).collect();
            let sealed = seal_object(&EventId([1; 32]), &[2; 32], &reference, &plain).unwrap();
            let mut slicer = Slicer::new(&sealed.header, SLICE_BYTES).unwrap();
            let mut slices = Vec::new();
            for chunk in &sealed.chunks {
                slicer.push(&chunk.sealed);
                while let Some(slice) = slicer.take(false) {
                    slices.push(slice);
                }
            }
            while let Some(slice) = slicer.take(true) {
                slices.push(slice);
            }
            let expected: Vec<(u64, Vec<u8>)> = (0u64..)
                .zip(sealed.bytes.chunks(SLICE_BYTES).map(<[u8]>::to_vec))
                .collect();
            assert_eq!(slices, expected, "size {size}");

            let mut reader = SliceReader::start(sealed.locator, None);
            let mut chunks = Vec::new();
            for (_, slice) in &slices {
                chunks.extend(reader.take(slice).unwrap());
            }
            let cut: Vec<Vec<u8>> = chunks.into_iter().map(|part| part.chunk).collect();
            let want: Vec<Vec<u8>> = sealed.chunks.iter().map(|c| c.sealed.clone()).collect();
            assert_eq!(cut, want, "size {size}");
        }
    }
}
