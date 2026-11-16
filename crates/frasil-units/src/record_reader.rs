//! Streaming record-object verification (units.md, 3.3; roster.md, 2.8).

use crate::limits::{CHUNK_BYTES, NONCE_BYTES, TAG_BYTES};
use crate::objects::{
    Header, HeaderName, ObjectKeys, chunk_aad, chunk_count, plain_length, stored_bytes_hasher,
};
use crate::record::{RecordBinding, RecordError, RecordKey};
use crate::{UnitClass, UnitError};
use frasil_base::ErrorClass;
use frasil_crypto::labels::CHECKPOINT_RECORD;
use frasil_crypto::primitives::{HmacSha256, Sha256Hasher, xchacha20poly1305_open};
use frasil_events::EventId;
use frasil_space::record_stream::RecordSink;
use zeroize::Zeroizing;

/// The object's verdict, before the record sink's own verdict is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordObjectOutcome {
    /// Step 0 failed, or chunks are missing: fetch the object again.
    NotTheObject,
    /// The first fault in the specified reading order.
    Refused(RecordError),
    /// All object checks and the checkpoint's size and digest passed.
    Opened,
}

/// Reads an object with one chunk of plaintext in memory. Sink output is
/// provisional until [`Self::finish`] returns [`RecordObjectOutcome::Opened`].
pub struct RecordObjectReader<'k> {
    space: EventId,
    binding: RecordBinding,
    header: Option<Header>,
    key: Option<Zeroizing<[u8; 32]>>,
    id: Option<HmacSha256>,
    stored: Sha256Hasher,
    digest: Sha256Hasher,
    early: Option<RecordError>,
    lengths: bool,
    late: Option<RecordError>,
    next: u64,
    size: u64,
    chunk: u64,
    lifetime: core::marker::PhantomData<RecordKey<'k>>,
}

impl<'k> RecordObjectReader<'k> {
    /// Checks the header, its self reference, and key availability, deferring
    /// their verdicts until the stored-byte digest and chunk lengths are known.
    pub fn new(
        header: &[u8],
        space: &EventId,
        key: Option<RecordKey<'k>>,
        binding: &RecordBinding,
    ) -> Self {
        Self::new_chunked(header, space, key, binding, CHUNK_BYTES)
    }

    /// [`Self::new`] with the chunk size used by conformance vectors.
    pub fn new_chunked(
        header: &[u8],
        space: &EventId,
        key: Option<RecordKey<'k>>,
        binding: &RecordBinding,
        chunk: usize,
    ) -> Self {
        let stored = stored_bytes_hasher(header);
        let parsed = stored
            .as_ref()
            .map_err(|e| *e)
            .and_then(|_| Header::read_as(header, HeaderName::Record));
        let mut early = parsed.as_ref().err().copied().map(RecordError::Object);
        let header = parsed.ok();
        if let Some(h) = &header
            && h.object_id != binding.locator[..32]
        {
            early = Some(UnitError::from(UnitClass::ObjectMismatch).into());
        }
        let mut late = None;
        let mut object_key = None;
        let mut id = None;
        if let Some(h) = &header {
            if h.self_reference() != Some(binding.checkpoint) {
                late = Some(RecordError::BadCheckpoint);
            }
            match key {
                None => {
                    late.get_or_insert(UnitError::from(ErrorClass::Sealed).into());
                }
                Some(RecordKey::Object(k)) => object_key = Some(Zeroizing::new(*k)),
                Some(RecordKey::Checkpoint(k)) => {
                    let keys = ObjectKeys::of(k);
                    object_key = Some(keys.object_key(&h.object_id));
                    id = Some(HmacSha256::new(&*keys.id_key));
                }
            }
        }
        let mut digest = Sha256Hasher::new();
        digest.update(CHECKPOINT_RECORD);
        Self {
            space: *space,
            binding: *binding,
            header,
            key: object_key,
            id,
            stored: stored.unwrap_or_default(),
            digest,
            early,
            lengths: chunk == 0,
            late,
            next: 0,
            size: 0,
            chunk: (chunk as u64).max(1),
            lifetime: core::marker::PhantomData,
        }
    }

    /// The header's number of chunks, if its structure could be read.
    pub fn chunk_count(&self) -> Option<u64> {
        self.header
            .as_ref()
            .map(|h| chunk_count(h.size, self.chunk))
    }

    /// Takes the next sealed chunk. Continue feeding after a fault so that
    /// step 0 can decide whether these bytes are the named object at all.
    pub fn feed(&mut self, index: u64, sealed: &[u8], sink: &mut dyn RecordSink) {
        self.stored.update(sealed);
        let ordered = index == self.next;
        self.next = self.next.saturating_add(1);
        let Some(h) = &self.header else {
            return;
        };
        if !ordered
            || index >= chunk_count(h.size, self.chunk)
            || sealed.len() as u64
                != plain_length(h.size, self.chunk, index) + (NONCE_BYTES + TAG_BYTES) as u64
        {
            self.lengths = true;
        }
        if self.early.is_some() || self.lengths || self.late.is_some() {
            return;
        }
        let Some(key) = &self.key else {
            return;
        };
        let Some((nonce, ciphertext)) = sealed.split_first_chunk::<NONCE_BYTES>() else {
            return;
        };
        let aad = chunk_aad(&self.space, &h.object_id, h.size, index);
        match xchacha20poly1305_open(key, nonce, &aad, ciphertext) {
            Ok(plain) => {
                let plain = Zeroizing::new(plain);
                self.size += plain.len() as u64;
                self.digest.update(&plain);
                if let Some(id) = &mut self.id {
                    id.update(&plain);
                }
                sink.feed(&plain);
            }
            Err(_) => self.late = Some(UnitError::from(ErrorClass::Decrypt).into()),
        }
    }

    /// Runs step 0, then reports faults in protocol order, and finally checks
    /// step 7 and the checkpoint's plaintext size and digest.
    pub fn finish(self) -> RecordObjectOutcome {
        if self.chunk_count().is_some_and(|n| self.next < n)
            || self.stored.finish() != self.binding.locator[32..]
        {
            return RecordObjectOutcome::NotTheObject;
        }
        let fault = self
            .early
            .or_else(|| {
                self.lengths
                    .then(|| UnitError::from(ErrorClass::Malformed).into())
            })
            .or(self.late);
        if let Some(fault) = fault {
            return RecordObjectOutcome::Refused(fault);
        }
        if let (Some(id), Some(h)) = (self.id, self.header)
            && id.finish() != h.object_id
        {
            return RecordObjectOutcome::Refused(UnitError::from(UnitClass::ObjectMismatch).into());
        }
        if self.size != self.binding.size || self.digest.finish() != self.binding.digest {
            return RecordObjectOutcome::Refused(RecordError::BadCheckpoint);
        }
        RecordObjectOutcome::Opened
    }
}
