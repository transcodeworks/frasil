//! Sealing an object one chunk at a time (units.md, 2.8 Objects), for a
//! writer that reads its plaintext from a source it can read twice rather
//! than holding it whole.
//!
//! The object ID is keyed over the whole plaintext and every chunk's
//! associated data names it, so a writer reads the source twice: once
//! through an [`ObjectIdPass`] for the ID and the size, then once through
//! an [`ObjectSealer`], which seals each chunk in order and hashes the
//! stored bytes as they are made. The sealer hashes the plaintext again as
//! it goes, so [`ObjectSealer::finish`] tells a source that changed between
//! the passes. The stored bytes and the locator are those of
//! [`seal_object`](super::seal_object) for the same plaintext.

use super::{Header, ObjectKeys, SealedChunk, chunk_count, plain_length, seal_chunk};
use crate::limits::{CHUNK_BYTES, MAX_OBJECT_BYTES};
use crate::{UnitClass, UnitError};
use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_crypto::primitives::{HmacSha256, Sha256Hasher};
use frasil_events::EventId;
use zeroize::Zeroizing;

/// The first pass over a plaintext: `object ID = HMAC(object_id_key(S),
/// plaintext)`, and the plaintext's length, fed in pieces of any size.
pub struct ObjectIdPass {
    mac: HmacSha256,
    size: u64,
}

impl core::fmt::Debug for ObjectIdPass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectIdPass")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl ObjectIdPass {
    /// A pass under the state whose object keys these are.
    pub fn new(keys: &ObjectKeys) -> Self {
        Self {
            mac: HmacSha256::new(&*keys.id_key),
            size: 0,
        }
    }

    /// Feeds the next piece of the plaintext.
    ///
    /// # Errors
    ///
    /// `TooLarge` once the plaintext passes 2^40 bytes.
    pub fn update(&mut self, plain: &[u8]) -> Result<(), UnitError> {
        let size = u64::try_from(plain.len())
            .ok()
            .and_then(|length| self.size.checked_add(length))
            .filter(|size| *size <= MAX_OBJECT_BYTES)
            .ok_or(UnitError::from(ErrorClass::TooLarge))?;
        self.mac.update(plain);
        self.size = size;
        Ok(())
    }

    /// The bytes fed so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The object ID and the plaintext's length.
    pub fn finish(self) -> ([u8; 32], u64) {
        (self.mac.finish(), self.size)
    }
}

/// What sealing an object yields once every chunk is sealed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SealedLocator {
    /// The object ID.
    pub id: [u8; 32],
    /// The digest of the stored bytes.
    pub digest: [u8; 32],
    /// The locator: ID, then digest.
    pub locator: Locator,
}

/// The second pass over a plaintext: each chunk sealed in order from its
/// plaintext alone, with the digest of the stored bytes hashed as they are
/// made. It holds no chunk: the caller keeps or sends each as it comes.
pub struct ObjectSealer {
    space: EventId,
    keys: ObjectKeys,
    object_key: Zeroizing<[u8; 32]>,
    id: [u8; 32],
    size: u64,
    header: Vec<u8>,
    chunk: u64,
    count: u64,
    next: u64,
    plain: HmacSha256,
    digest: Sha256Hasher,
}

impl core::fmt::Debug for ObjectSealer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ObjectSealer")
            .field("size", &self.size)
            .field("count", &self.count)
            .field("next", &self.next)
            .finish_non_exhaustive()
    }
}

impl ObjectSealer {
    /// A sealer of the object of this ID and size under the state whose
    /// content key and key reference these are, in chunks of 1,048,536
    /// bytes.
    ///
    /// # Errors
    ///
    /// `TooLarge` for a size over 2^40 bytes.
    pub fn new(
        space: &EventId,
        content_key: &[u8; 32],
        key_reference: &[u8],
        object_id: [u8; 32],
        size: u64,
    ) -> Result<Self, UnitError> {
        Self::new_chunked(
            space,
            content_key,
            key_reference,
            object_id,
            size,
            CHUNK_BYTES,
        )
    }

    /// [`ObjectSealer::new`] with another chunk size, as the vectors use.
    ///
    /// # Errors
    ///
    /// `TooLarge` for a size over 2^40 bytes or a header whose length does
    /// not fit four bytes; `Malformed` for a chunk size of 0.
    pub fn new_chunked(
        space: &EventId,
        content_key: &[u8; 32],
        key_reference: &[u8],
        object_id: [u8; 32],
        size: u64,
        chunk: usize,
    ) -> Result<Self, UnitError> {
        if size > MAX_OBJECT_BYTES {
            return Err(ErrorClass::TooLarge.into());
        }
        let chunk = u64::try_from(chunk)
            .ok()
            .filter(|chunk| *chunk > 0)
            .ok_or(UnitError::from(ErrorClass::Malformed))?;
        let keys = ObjectKeys::of(content_key);
        let object_key = keys.object_key(&object_id);
        let header = Header {
            object_id,
            key_reference: key_reference.to_vec(),
            size,
        }
        .encode();
        let length =
            u32::try_from(header.len()).map_err(|_| UnitError::from(ErrorClass::TooLarge))?;
        let mut digest = Sha256Hasher::new();
        digest.update(&length.to_be_bytes());
        digest.update(&header);
        let plain = HmacSha256::new(&*keys.id_key);
        Ok(Self {
            space: *space,
            keys,
            object_key,
            id: object_id,
            size,
            header,
            chunk,
            count: chunk_count(size, chunk),
            next: 0,
            plain,
            digest,
        })
    }

    /// The header's bytes, which part 0 of the object holds.
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// The object ID the sealer was given.
    pub fn object_id(&self) -> [u8; 32] {
        self.id
    }

    /// The plaintext's length.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// `n`, the object's chunk count.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The index of the next chunk to seal.
    pub fn next_index(&self) -> u64 {
        self.next
    }

    /// Where the next chunk's plaintext starts, and its length: `None`
    /// once every chunk is sealed.
    pub fn next_range(&self) -> Option<(u64, u64)> {
        (self.next < self.count).then(|| {
            (
                self.next * self.chunk,
                plain_length(self.size, self.chunk, self.next),
            )
        })
    }

    /// Seals the next chunk from its plaintext, `plain_i`, and hashes its
    /// sealed bytes into the digest.
    ///
    /// # Errors
    ///
    /// `Malformed` once every chunk is sealed, or for a plaintext of
    /// another length than the chunk's.
    pub fn seal_next(&mut self, plain: &[u8]) -> Result<SealedChunk, UnitError> {
        let (_, length) = self
            .next_range()
            .ok_or(UnitError::from(ErrorClass::Malformed))?;
        if u64::try_from(plain.len()).ok() != Some(length) {
            return Err(ErrorClass::Malformed.into());
        }
        let sealed = seal_chunk(
            &self.space,
            &self.keys,
            &self.object_key,
            &self.id,
            self.size,
            self.next,
            plain,
        );
        self.plain.update(plain);
        self.digest.update(&sealed.sealed);
        self.next += 1;
        Ok(sealed)
    }

    /// The locator, once every chunk is sealed.
    ///
    /// # Errors
    ///
    /// `Malformed` while a chunk is left; `ObjectMismatch` when the
    /// plaintext sealed does not have the object ID the sealer was given,
    /// as when the source changed between the passes.
    pub fn finish(self) -> Result<SealedLocator, UnitError> {
        if self.next < self.count {
            return Err(ErrorClass::Malformed.into());
        }
        if self.plain.finish() != self.id {
            return Err(UnitClass::ObjectMismatch.into());
        }
        let digest = self.digest.finish();
        let mut locator = [0; 64];
        locator[..32].copy_from_slice(&self.id);
        locator[32..].copy_from_slice(&digest);
        Ok(SealedLocator {
            id: self.id,
            digest,
            locator,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::{seal_object, seal_object_chunked};
    use frasil_keys::RotationSet;

    fn plaintext(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i * 31 + i / 7) as u8).collect()
    }

    /// Both passes over a plaintext, fed in pieces of `piece` bytes:
    /// the stored bytes and the locator.
    fn seal_in_passes(
        space: &EventId,
        key: &[u8; 32],
        reference: &[u8],
        plain: &[u8],
        chunk: usize,
        piece: usize,
    ) -> (Vec<u8>, Locator) {
        let mut pass = ObjectIdPass::new(&ObjectKeys::of(key));
        for part in plain.chunks(piece.max(1)) {
            pass.update(part).unwrap();
        }
        let (id, size) = pass.finish();
        let mut sealer = ObjectSealer::new_chunked(space, key, reference, id, size, chunk).unwrap();
        let mut bytes = (sealer.header().len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(sealer.header());
        while let Some((start, length)) = sealer.next_range() {
            let (start, length) = (start as usize, length as usize);
            let sealed = sealer.seal_next(&plain[start..start + length]).unwrap();
            bytes.extend_from_slice(&sealed.sealed);
        }
        let sealed = sealer.finish().unwrap();
        (bytes, sealed.locator)
    }

    /// The sealer gives `seal_object`'s stored bytes and locator, byte for
    /// byte: empty, under one chunk, one chunk exactly, an exact multiple
    /// of chunks, and several chunks with a remainder.
    #[test]
    fn sealing_a_chunk_at_a_time_is_sealing_whole() {
        let space = EventId([5; 32]);
        let key = [9u8; 32];
        let reference = RotationSet::single(EventId([3; 32])).encode();
        let chunk = 64;
        for size in [0, 1, 63, 64, 128, 64 * 3, 64 * 3 + 17] {
            let plain = plaintext(size);
            let whole = seal_object_chunked(&space, &key, &reference, &plain, chunk).unwrap();
            for piece in [1, 7, 64, 1000] {
                let (bytes, locator) =
                    seal_in_passes(&space, &key, &reference, &plain, chunk, piece);
                assert_eq!(bytes, whole.bytes, "size {size}, pieces of {piece}");
                assert_eq!(locator, whole.locator, "size {size}, pieces of {piece}");
            }
        }
    }

    /// The same at the real chunk size, across the boundaries of
    /// 1,048,536-byte chunks.
    #[test]
    fn sealing_a_chunk_at_a_time_is_sealing_whole_at_the_chunk_size() {
        let space = EventId([6; 32]);
        let key = [4u8; 32];
        let reference = RotationSet::single(EventId([2; 32])).encode();
        for size in [0, 1000, CHUNK_BYTES, 2 * CHUNK_BYTES, 2 * CHUNK_BYTES + 5] {
            let plain = plaintext(size);
            let whole = seal_object(&space, &key, &reference, &plain).unwrap();
            let (bytes, locator) =
                seal_in_passes(&space, &key, &reference, &plain, CHUNK_BYTES, 64 * 1024);
            assert_eq!(bytes, whole.bytes, "size {size}");
            assert_eq!(locator, whole.locator, "size {size}");
        }
    }

    /// A second pass over other bytes than the first is `ObjectMismatch`,
    /// and a chunk of the wrong length, or one too many, is `Malformed`.
    #[test]
    fn a_source_that_changed_between_the_passes_is_refused() {
        let space = EventId([7; 32]);
        let key = [1u8; 32];
        let reference = RotationSet::single(EventId([8; 32])).encode();
        let plain = plaintext(100);
        let mut pass = ObjectIdPass::new(&ObjectKeys::of(&key));
        pass.update(&plain).unwrap();
        let (id, size) = pass.finish();

        let mut sealer = ObjectSealer::new_chunked(&space, &key, &reference, id, size, 64).unwrap();
        assert_eq!(
            sealer.seal_next(&plain[..10]),
            Err(ErrorClass::Malformed.into())
        );
        sealer.seal_next(&plain[..64]).unwrap();
        let mut early = ObjectSealer::new_chunked(&space, &key, &reference, id, size, 64).unwrap();
        early.seal_next(&plain[..64]).unwrap();
        assert_eq!(
            early.finish(),
            Err(ErrorClass::Malformed.into()),
            "a chunk is left"
        );
        let mut changed = plain[64..].to_vec();
        changed[0] ^= 1;
        sealer.seal_next(&changed).unwrap();
        assert_eq!(sealer.seal_next(&[]), Err(ErrorClass::Malformed.into()));
        assert_eq!(sealer.finish(), Err(UnitClass::ObjectMismatch.into()));
    }

    /// An ID pass refuses to pass 2^40 bytes.
    #[test]
    fn an_id_pass_stops_at_the_largest_object() {
        let mut pass = ObjectIdPass::new(&ObjectKeys::of(&[0; 32]));
        pass.size = MAX_OBJECT_BYTES - 1;
        assert_eq!(pass.update(&[0, 0]), Err(ErrorClass::TooLarge.into()));
        pass.update(&[0]).unwrap();
        assert_eq!(pass.size(), MAX_OBJECT_BYTES);
    }
}
