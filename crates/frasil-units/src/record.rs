//! A checkpoint's record object (roster.md, 2.8 The checkpoint record, "The
//! record object"; units.md, 2.8 Objects and 3.3 Reading an object).
//!
//! A checkpoint's record always travels as an object, in one form whatever
//! the space's size:
//!
//! - It is sealed as every object is, chunked, under the checkpoint's own
//!   content key `k_R`. Its header's key reference is the checkpoint's self
//!   reference (keys.md, "Reading key names"), since the checkpoint's ID does
//!   not exist when the record is sealed ([`seal_record`]).
//! - The checkpoint binds it twice ([`RecordBinding`]): by the locator, and
//!   by `digest` and `size` over the plaintext, where
//!   `digest = SHA-256("frasil/checkpoint-record/v1" || record)`
//!   ([`record_digest`]), and `size` is at most [`MAX_RECORD_BYTES`].
//! - Reading it (`read_record_object`), in order: units.md's "Reading an
//!   object" under the locator, steps 0 to 4, the header's key 3 a self
//!   reference (`Malformed` otherwise); that self reference is the
//!   checkpoint's own, `0x00 || author || u64be(seq)` of its envelope, else
//!   `BadCheckpoint`, before any chunk opens; then steps 5 to 7 with `k_R`,
//!   or 5 and 6 with the record's object key handed over (a newcomer's,
//!   units.md, "The space snapshot", key 13); then the plaintext's length is
//!   `size` and its digest `digest`, else `BadCheckpoint`. The locator binds
//!   that very object, header included, so a wrong one is the checkpoint
//!   author's own fault and no other object can repair it. Reading the
//!   record's map, and its epoch against the checkpoint's, is the roster's.
//!
//! A peer, which cannot tell a record object from any other, runs steps 0
//! to 4 and accepts either form of key 3
//! ([`check_stored`](crate::objects::check_stored)).
//!
//! A replica that lacks the object, or a key that opens it, holds the
//! checkpoint as `Sealed` ([`RecordError::Object`] with that class) and
//! fetches the object by its locator.

use crate::UnitError;
use crate::limits::CHUNK_BYTES;
use crate::objects::{ObjectKeys, SealedObject, seal_object_chunked};
#[cfg(any(test, feature = "oracle"))]
use crate::{
    UnitClass,
    objects::{HeaderName, check_stored_as, open_chunks},
};
use frasil_adapter::Locator;
use frasil_base::ErrorClass;
use frasil_crypto::labels::CHECKPOINT_RECORD;
use frasil_crypto::primitives::sha256;
use frasil_events::EventId;
use frasil_keys::SelfRef;
use frasil_space::{CheckpointPart, RecordObject, RecordObjects};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The most bytes of a checkpoint's record: 256 MiB (roster.md, 2.2 The
/// roster part, `size`); more is `TooLarge`.
pub const MAX_RECORD_BYTES: u64 = 268_435_456;

/// `digest = SHA-256("frasil/checkpoint-record/v1" || record)`.
pub fn record_digest(record: &[u8]) -> [u8; 32] {
    sha256(&[CHECKPOINT_RECORD, record])
}

/// What a checkpoint binds of its record object: its roster part's
/// locator, and the record's `size` and `digest` over the plaintext; and
/// its envelope's author and `seq`, which the object's header names as the
/// checkpoint's self reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordBinding {
    /// The checkpoint's self reference: its envelope's author and `seq`.
    pub checkpoint: SelfRef,
    /// The record object's locator.
    pub locator: Locator,
    /// The record's length in bytes.
    pub size: u64,
    /// [`record_digest`] of the record.
    pub digest: [u8; 32],
}

impl RecordBinding {
    /// Whether an object header's size is the record's: a reader that holds
    /// the header may stop fetching chunks of an object whose size differs,
    /// which can only read as `BadCheckpoint`.
    pub fn admits_size(&self, header_size: u64) -> bool {
        header_size == self.size
    }

    /// Whether a record's plaintext is the one bound: its length is `size`
    /// and its digest `digest`.
    pub fn binds(&self, record: &[u8]) -> bool {
        u64::try_from(record.len()).is_ok_and(|size| size == self.size)
            && record_digest(record) == self.digest
    }
}

/// A sealed record object and what its checkpoint binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedRecord {
    /// The object, every intermediate value with it.
    pub object: SealedObject,
    /// The locator, `size` and `digest` the checkpoint's roster part names.
    pub binding: RecordBinding,
}

/// Seals a checkpoint's record as its object: under `k_R`, the checkpoint's
/// own content key, with the checkpoint's self reference, the author and
/// `seq` it is about to sign under, as the header's key reference. Its
/// author uploads the object before it signs the checkpoint.
///
/// # Errors
///
/// `TooLarge` for a record of more than [`MAX_RECORD_BYTES`].
pub fn seal_record(
    space: &EventId,
    checkpoint_key: &[u8; 32],
    own: SelfRef,
    record: &[u8],
) -> Result<SealedRecord, ErrorClass> {
    seal_record_chunked(space, checkpoint_key, own, record, CHUNK_BYTES)
}

/// [`seal_record`] with another chunk size, as tests use.
///
/// # Errors
///
/// As [`seal_record`]; `Malformed` for a chunk size of 0.
pub fn seal_record_chunked(
    space: &EventId,
    checkpoint_key: &[u8; 32],
    own: SelfRef,
    record: &[u8],
    chunk: usize,
) -> Result<SealedRecord, ErrorClass> {
    let size = u64::try_from(record.len()).map_err(|_| ErrorClass::TooLarge)?;
    if size > MAX_RECORD_BYTES {
        return Err(ErrorClass::TooLarge);
    }
    let object = seal_object_chunked(space, checkpoint_key, &own.encode(), record, chunk)?;
    let binding = RecordBinding {
        checkpoint: own,
        locator: object.locator,
        size,
        digest: record_digest(record),
    };
    Ok(SealedRecord { object, binding })
}

/// The record object's own key, from `k_R`: what a snapshot's sender hands
/// a newcomer at key 13, which opens that object alone (units.md, 2.8
/// Objects).
pub fn record_object_key(checkpoint_key: &[u8; 32], locator: &Locator) -> Zeroizing<[u8; 32]> {
    let mut id = [0; 32];
    id.copy_from_slice(&locator[..32]);
    ObjectKeys::of(checkpoint_key).object_key(&id)
}

/// The key a reader opens a record object with.
#[derive(Debug, Clone, Copy)]
pub enum RecordKey<'k> {
    /// `k_R`, the checkpoint's own content key: steps 0 to 7.
    Checkpoint(&'k [u8; 32]),
    /// The record's object key, handed over: steps 0 to 6.
    Object(&'k [u8; 32]),
}

/// Why a record object did not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordError {
    /// units.md's "Reading an object" refused it: `ObjectMismatch`,
    /// `Malformed`, `UnsupportedVersion`, `TooLarge`, `Sealed` (no key, the
    /// checkpoint held) or `Decrypt`.
    Object(UnitError),
    /// Its header names another event than the checkpoint by its self
    /// reference, or it opened and its plaintext is not the record the
    /// checkpoint binds by `size` and `digest`: the checkpoint is void
    /// (`BadCheckpoint`, roster.md).
    BadCheckpoint,
}

impl From<UnitError> for RecordError {
    fn from(class: UnitError) -> Self {
        Self::Object(class)
    }
}

/// Reads a checkpoint's record object (roster.md, "The record object",
/// "Reading it"): section 3.3, steps 0 to 4, under the binding's locator,
/// the header's key 3 a self reference (`Malformed` otherwise, at step 2);
/// that self reference the binding's `checkpoint` (`BadCheckpoint`); then
/// steps 5 to 7 with `key`, or with none (`Sealed`); then the plaintext's
/// length is `size` and its digest `digest`. Returns the record's bytes,
/// which the roster reads.
///
/// # Errors
///
/// [`RecordError::Object`] with section 3.3's class, in its order;
/// [`RecordError::BadCheckpoint`] for a header naming another event, or a
/// plaintext that is not the one bound.
#[cfg(any(test, feature = "oracle"))]
pub fn read_record_object(
    data: &[u8],
    space: &EventId,
    key: Option<RecordKey<'_>>,
    binding: &RecordBinding,
) -> Result<Vec<u8>, RecordError> {
    read_record_object_chunked(data, space, key, binding, CHUNK_BYTES)
}

/// `read_record_object` with another chunk size, as tests use.
///
/// # Errors
///
/// As `read_record_object`.
#[cfg(any(test, feature = "oracle"))]
pub fn read_record_object_chunked(
    data: &[u8],
    space: &EventId,
    key: Option<RecordKey<'_>>,
    binding: &RecordBinding,
    chunk: usize,
) -> Result<Vec<u8>, RecordError> {
    // Steps 0 to 4, the header a self reference.
    let stored = check_stored_as(data, &binding.locator, chunk, HeaderName::Record)?;
    let header = &stored.header;
    // The header names this very checkpoint: the locator binds it, so
    // another name is the checkpoint's own fault, found before any chunk
    // opens (units.md, 3.3 Reading an object).
    if header.self_reference() != Some(binding.checkpoint) {
        return Err(RecordError::BadCheckpoint);
    }
    // 5. The reader holds k_R, or the object key.
    let record = match key {
        None => return Err(UnitError::from(ErrorClass::Sealed).into()),
        Some(RecordKey::Checkpoint(content_key)) => {
            let keys = ObjectKeys::of(content_key);
            // 6. Each chunk opens under the object key.
            let plaintext = open_chunks(&stored, space, &keys.object_key(&header.object_id))?;
            // 7. The whole plaintext's ID.
            if keys.object_id(&plaintext) != header.object_id {
                return Err(UnitError::from(UnitClass::ObjectMismatch).into());
            }
            plaintext
        }
        // 6. Step 7 needs k_R and is skipped: step 0 binds the bytes to the
        //    locator, and step 6 to the key.
        Some(RecordKey::Object(object_key)) => open_chunks(&stored, space, object_key)?,
    };
    // The size and digest the checkpoint names.
    if !binding.binds(&record) {
        return Err(RecordError::BadCheckpoint);
    }
    Ok(record)
}

/// A completed object and record read, safe to hand to checkpoint judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordRead {
    /// The bound roster part.
    pub part: CheckpointPart,
    /// The validated outcome; any provisional parser state has been discarded.
    pub outcome: RecordObject,
    /// The object verification outcome, before the record parser's verdict.
    pub object_outcome: crate::record_reader::RecordObjectOutcome,
}

impl RecordRead {
    /// Resolves the object checks before the parser's deferred faults.
    pub fn finish(
        reader: crate::record_reader::RecordObjectReader<'_>,
        sink: frasil_space::RecordStream,
        part: &CheckpointPart,
        handed: bool,
    ) -> Self {
        use crate::record_reader::RecordObjectOutcome;
        use frasil_space::{ReadRecord, RecordFault};
        let object_outcome = reader.finish();
        let outcome = match object_outcome {
            RecordObjectOutcome::NotTheObject => RecordObject::Missing,
            RecordObjectOutcome::Refused(RecordError::Object(class))
                if class == UnitError::from(ErrorClass::Sealed)
                    || (handed && class == UnitError::from(ErrorClass::Decrypt)) =>
            {
                RecordObject::Missing
            }
            RecordObjectOutcome::Refused(_) => RecordObject::Refused,
            RecordObjectOutcome::Opened => match sink.finish() {
                Ok(ReadRecord::Built(record)) if record.epoch == part.epoch => {
                    RecordObject::Read(Arc::new(record))
                }
                Ok(ReadRecord::Summary(summary)) if summary.epoch == part.epoch => {
                    RecordObject::Summary(Arc::new(summary))
                }
                Err(RecordFault::Extension(link)) => {
                    RecordObject::Extension(link.filter(|(epoch, _)| *epoch == part.epoch))
                }
                _ => RecordObject::Refused,
            },
        };
        Self {
            part: part.clone(),
            outcome,
            object_outcome,
        }
    }
}

/// Validated record reads, made outside checkpoint judgement.
#[derive(Debug, Clone, Copy)]
pub struct HeldRecords<'a> {
    /// Completed reads by checkpoint ID.
    pub reads: &'a BTreeMap<EventId, RecordRead>,
}
impl RecordObjects for HeldRecords<'_> {
    fn record_object(&self, checkpoint: EventId, part: &CheckpointPart) -> RecordObject {
        self.reads
            .get(&checkpoint)
            .filter(|read| read.part == *part)
            .map(|read| read.outcome.clone())
            .unwrap_or(RecordObject::Missing)
    }
}

/// Whole-buffer comparison reader for conformance tests and fuzzing.
#[cfg(any(test, feature = "oracle"))]
pub mod oracle {
    use super::*;
    use frasil_events::HeldEnvelopes;
    use frasil_space::Keyring;
    /// The record objects a replica holds, read for the roster's checkpoint
    /// rules ([`frasil_space::RecordObjects`]): the stored object bytes by
    /// locator, the checkpoints' own content keys `k_R` (each rotation's, in
    /// the keyring the replica opens space events with), and the record object
    /// keys a snapshot handed over (units.md, "The space snapshot", key 13), by
    /// checkpoint; and the checkpoints' envelopes, whose author and `seq` the
    /// object's header must name.
    #[derive(Clone, Copy)]
    pub struct OracleRecords<'a> {
        /// The space ID.
        pub space: EventId,
        /// Where the checkpoints' envelopes are read: the space's log, or what
        /// the replica keeps beside it.
        pub envelopes: &'a dyn HeldEnvelopes,
        /// The objects the replica holds, by locator.
        pub objects: &'a BTreeMap<Locator, Vec<u8>>,
        /// The keys the replica opens space events with: a checkpoint rotates,
        /// so its `k_R` is its rotation's content key.
        pub keys: &'a Keyring,
        /// Record object keys handed over, by checkpoint.
        pub object_keys: &'a BTreeMap<EventId, Zeroizing<[u8; 32]>>,
    }

    impl core::fmt::Debug for OracleRecords<'_> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("OracleRecords")
                .field("space", &self.space)
                .field("objects", &self.objects.len())
                .field("object_keys", &self.object_keys.keys().collect::<Vec<_>>())
                .finish_non_exhaustive()
        }
    }

    impl RecordObjects for OracleRecords<'_> {
        /// Reads the record object a checkpoint names (`read_record_object`):
        ///
        /// - `Missing`, and the checkpoint held, while the replica lacks the
        ///   object or a key for it, or holds bytes that are not the object its
        ///   locator names (step 0: it fetches them again), or a handed object
        ///   key that does not open it (the sender's key, not the object, may
        ///   be at fault), or while it lacks the checkpoint's envelope;
        /// - `Refused`, and the checkpoint `BadCheckpoint`, for an object that
        ///   is the one its locator names and whose header names another event
        ///   than the checkpoint, or that fails to read under `k_R`, or whose
        ///   plaintext is not the record the checkpoint binds;
        /// - `Opened` with the record's bytes otherwise.
        fn record_object(&self, checkpoint: EventId, part: &CheckpointPart) -> RecordObject {
            let Some(envelope) = self.envelopes.envelope(checkpoint) else {
                return RecordObject::Missing;
            };
            let binding = RecordBinding {
                checkpoint: SelfRef::new(*envelope.author(), envelope.seq()),
                locator: part.locator,
                size: part.size,
                digest: part.digest,
            };
            let Some(data) = self.objects.get(&binding.locator) else {
                return RecordObject::Missing;
            };
            if sha256(&[data]) != binding.locator[32..] {
                return RecordObject::Missing;
            }
            let (key, handed) = match (
                self.keys.rotations.get(&checkpoint),
                self.object_keys.get(&checkpoint),
            ) {
                (Some(k_r), _) => (Some(RecordKey::Checkpoint(k_r)), false),
                (None, Some(object_key)) => (Some(RecordKey::Object(object_key)), true),
                // Without a key the header is still checked: `Sealed` after it.
                (None, None) => (None, false),
            };
            match read_record_object(data, &self.space, key, &binding) {
                Ok(plaintext) => match frasil_space::Record::read_object(&plaintext, part) {
                    Ok(record) => RecordObject::Read(Arc::new(record)),
                    Err(class) if class.shared() == Some(ErrorClass::ExtensionRequired) => {
                        RecordObject::Extension(
                            frasil_space::checkpoint_record::read_link(&plaintext)
                                .filter(|(epoch, _)| *epoch == part.epoch),
                        )
                    }
                    Err(_) => RecordObject::Refused,
                },
                Err(RecordError::Object(class)) if class == UnitError::from(ErrorClass::Sealed) => {
                    RecordObject::Missing
                }
                Err(RecordError::Object(class))
                    if handed && class == UnitError::from(ErrorClass::Decrypt) =>
                {
                    RecordObject::Missing
                }
                Err(_) => RecordObject::Refused,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::oracle::OracleRecords;
    use super::*;
    use crate::objects::{Header, check_stored, read_object, seal_object_chunked};
    use frasil_crypto::device::DeviceId;
    use frasil_keys::RotationSet;
    use frasil_space::Keyring;

    const SPACE: EventId = EventId([0x5a; 32]);
    const K_R: [u8; 32] = [0x11; 32];

    fn own() -> SelfRef {
        SelfRef::new(DeviceId([0x22; 32]), 9)
    }

    #[test]
    fn a_record_reads_back_under_its_key_and_its_object_key() {
        let record = b"a record of three chunks and a little more".repeat(5);
        let sealed = seal_record_chunked(&SPACE, &K_R, own(), &record, 64).unwrap();
        assert!(sealed.object.chunks.len() > 2);
        assert_eq!(sealed.binding.size, record.len() as u64);
        assert_eq!(sealed.binding.digest, record_digest(&record));
        let header = Header::read(&sealed.object.header).unwrap();
        assert_eq!(header.self_reference(), Some(own()));
        assert!(sealed.binding.admits_size(header.size));
        let bytes = &sealed.object.bytes;
        assert_eq!(
            read_record_object_chunked(
                bytes,
                &SPACE,
                Some(RecordKey::Checkpoint(&K_R)),
                &sealed.binding,
                64
            ),
            Ok(record.clone())
        );
        let object_key = record_object_key(&K_R, &sealed.binding.locator);
        assert_eq!(
            read_record_object_chunked(
                bytes,
                &SPACE,
                Some(RecordKey::Object(&object_key)),
                &sealed.binding,
                64
            ),
            Ok(record.clone())
        );
        // A peer stores it: steps 0 to 4 read either header form.
        assert!(crate::objects::check_stored_chunked(bytes, &sealed.binding.locator, 64).is_ok());
        // Without a key, the checkpoint is held.
        assert_eq!(
            read_record_object_chunked(bytes, &SPACE, None, &sealed.binding, 64),
            Err(RecordError::Object(ErrorClass::Sealed.into()))
        );
        // As a unit's object, a self reference is Malformed.
        assert_eq!(
            crate::objects::read_object_chunked(
                bytes,
                &SPACE,
                Some(&K_R),
                &sealed.binding.locator,
                64
            ),
            Err(ErrorClass::Malformed.into())
        );
    }

    #[test]
    fn an_object_that_opens_but_is_not_the_bound_record_voids_the_checkpoint() {
        let record = b"the record".to_vec();
        let sealed = seal_record(&SPACE, &K_R, own(), &record).unwrap();
        let bytes = &sealed.object.bytes;
        let key = Some(RecordKey::Checkpoint(&K_R));
        // Another digest, or another size: BadCheckpoint.
        let digest = RecordBinding {
            digest: record_digest(b"another record"),
            ..sealed.binding
        };
        assert_eq!(
            read_record_object(bytes, &SPACE, key, &digest),
            Err(RecordError::BadCheckpoint)
        );
        let size = RecordBinding {
            size: sealed.binding.size + 1,
            ..sealed.binding
        };
        assert!(!size.admits_size(record.len() as u64));
        assert_eq!(
            read_record_object(bytes, &SPACE, key, &size),
            Err(RecordError::BadCheckpoint)
        );
        // The digest is over the label and the record, not the record
        // alone.
        assert_ne!(record_digest(&record), sha256(&[&record]));
        // Another locator's digest: ObjectMismatch, before any key.
        let mut locator = sealed.binding.locator;
        locator[40] ^= 1;
        let elsewhere = RecordBinding {
            locator,
            ..sealed.binding
        };
        assert_eq!(
            read_record_object(bytes, &SPACE, key, &elsewhere),
            Err(RecordError::Object(UnitClass::ObjectMismatch.into()))
        );
        // Under another k_R it does not open.
        assert_eq!(
            read_record_object(
                bytes,
                &SPACE,
                Some(RecordKey::Checkpoint(&[0x12; 32])),
                &sealed.binding
            ),
            Err(RecordError::Object(ErrorClass::Decrypt.into()))
        );
        // A handed object key of another object does not open it.
        assert_eq!(
            read_record_object(
                bytes,
                &SPACE,
                Some(RecordKey::Object(&[0x13; 32])),
                &sealed.binding
            ),
            Err(RecordError::Object(ErrorClass::Decrypt.into()))
        );
    }

    #[test]
    fn a_record_object_has_a_self_reference_and_nothing_else() {
        // An object under a state of rotations is no record object.
        let state = RotationSet::single(EventId([3; 32])).encode();
        let object = seal_object_chunked(&SPACE, &K_R, &state, b"the record", 64).unwrap();
        let binding = RecordBinding {
            checkpoint: own(),
            locator: object.locator,
            size: 10,
            digest: record_digest(b"the record"),
        };
        assert_eq!(
            read_record_object_chunked(
                &object.bytes,
                &SPACE,
                Some(RecordKey::Checkpoint(&K_R)),
                &binding,
                64
            ),
            Err(RecordError::Object(ErrorClass::Malformed.into()))
        );
        assert_eq!(
            read_object(&object.bytes, &SPACE, Some(&K_R), &object.locator),
            Ok(b"the record".to_vec())
        );
        // A self reference with a byte after it, or cut short, is Malformed
        // at step 2 whatever the form.
        let mut long = own().encode().to_vec();
        long.push(0);
        let mut short = own().encode().to_vec();
        short.pop();
        for name in [long, short] {
            let object = seal_object_chunked(&SPACE, &K_R, &name, b"x", 64).unwrap();
            assert_eq!(
                check_stored(&object.bytes, &object.locator),
                Err(ErrorClass::Malformed.into())
            );
        }
    }

    fn part(binding: &RecordBinding) -> CheckpointPart {
        CheckpointPart {
            epoch: 1,
            digest: binding.digest,
            size: binding.size,
            locator: binding.locator,
        }
    }

    /// A signed space event standing for a checkpoint: its author and
    /// `seq` are what its record object's header names.
    fn checkpoint_event(seq: u64) -> frasil_events::Event {
        use frasil_crypto::schemes::{Scheme, Signer};
        let signer = Signer::from_seeds(&[7; 32], &[107; 32], None);
        let prev = EventId([0x33; 32]);
        let envelope = frasil_events::Envelope {
            kind: frasil_events::kind::SPACE,
            log: Some(SPACE),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev: Some(prev),
            parents: vec![prev],
            cuts: Vec::new(),
            body: b"a checkpoint".to_vec(),
            scheme: Scheme::Hybrid,
        };
        frasil_events::decode(&envelope.sign(&signer)).unwrap()
    }

    #[test]
    fn a_record_object_names_its_own_checkpoint() {
        let record = b"the record".to_vec();
        let sealed = seal_record(&SPACE, &K_R, own(), &record).unwrap();
        let bytes = &sealed.object.bytes;
        // Another seq, or another author: BadCheckpoint, before any key
        // and whatever key is held.
        for checkpoint in [
            SelfRef::new(own().author, 10),
            SelfRef::new(DeviceId([0x23; 32]), 9),
        ] {
            let binding = RecordBinding {
                checkpoint,
                ..sealed.binding
            };
            for key in [None, Some(RecordKey::Checkpoint(&K_R))] {
                assert_eq!(
                    read_record_object(bytes, &SPACE, key, &binding),
                    Err(RecordError::BadCheckpoint)
                );
            }
        }
        // Its own: Sealed without a key, the record with one.
        assert_eq!(
            read_record_object(bytes, &SPACE, None, &sealed.binding),
            Err(RecordError::Object(ErrorClass::Sealed.into()))
        );
        assert_eq!(
            read_record_object(
                bytes,
                &SPACE,
                Some(RecordKey::Checkpoint(&K_R)),
                &sealed.binding
            ),
            Ok(record)
        );
    }

    #[test]
    fn held_records_read_for_the_roster() {
        let event = checkpoint_event(9);
        let checkpoint = event.id();
        let envelopes = BTreeMap::from([(checkpoint, event.clone())]);
        let own = SelfRef::new(*event.author(), event.seq());
        let typed = Arc::new(frasil_space::Record {
            epoch: 1,
            previous: None,
            members: Vec::new(),
            policy: frasil_space::Policy::default(),
            tips: BTreeMap::new(),
            forks: BTreeMap::new(),
            heard: Vec::new(),
        });
        let record = typed.encode();
        let sealed = seal_record(&SPACE, &K_R, own, &record).unwrap();
        let part = part(&sealed.binding);
        let mut objects = BTreeMap::new();
        let mut keys = Keyring::default();
        let mut object_keys = BTreeMap::new();
        let read = |objects: &BTreeMap<Locator, Vec<u8>>,
                    keys: &Keyring,
                    object_keys: &BTreeMap<EventId, Zeroizing<[u8; 32]>>,
                    part: &CheckpointPart| {
            OracleRecords {
                space: SPACE,
                envelopes: &envelopes,
                objects,
                keys,
                object_keys,
            }
            .record_object(checkpoint, part)
        };
        // Without the object, or without a key, the checkpoint is held.
        assert_eq!(
            read(&objects, &keys, &object_keys, &part),
            RecordObject::Missing
        );
        objects.insert(sealed.binding.locator, sealed.object.bytes.clone());
        assert_eq!(
            read(&objects, &keys, &object_keys, &part),
            RecordObject::Missing
        );
        // A newcomer's handed object key opens it; another key holds it.
        object_keys.insert(checkpoint, Zeroizing::new([0x13; 32]));
        assert_eq!(
            read(&objects, &keys, &object_keys, &part),
            RecordObject::Missing
        );
        object_keys.insert(checkpoint, record_object_key(&K_R, &sealed.binding.locator));
        assert_eq!(
            read(&objects, &keys, &object_keys, &part),
            RecordObject::Read(Arc::clone(&typed))
        );
        // Under the checkpoint's own content key.
        object_keys.clear();
        keys.rotations.insert(checkpoint, Zeroizing::new(K_R));
        assert_eq!(
            read(&objects, &keys, &object_keys, &part),
            RecordObject::Read(Arc::clone(&typed))
        );
        // Bytes that are not the object the locator names: fetched again.
        let mut other = objects.clone();
        other.get_mut(&sealed.binding.locator).unwrap()[10] ^= 1;
        assert_eq!(
            read(&other, &keys, &object_keys, &part),
            RecordObject::Missing
        );
        // The object the locator names, not the record bound: void.
        let wrong = CheckpointPart {
            digest: record_digest(b"another record"),
            ..part
        };
        assert_eq!(
            read(&objects, &keys, &object_keys, &wrong),
            RecordObject::Refused
        );
        // The object the locator names does not open under k_R: void.
        keys.rotations
            .insert(checkpoint, Zeroizing::new([0x12; 32]));
        assert_eq!(
            read(&objects, &keys, &object_keys, &part),
            RecordObject::Refused
        );
        // A record object naming another checkpoint: void, with no key.
        let other = seal_record(&SPACE, &K_R, SelfRef::new(own.author, 8), &record).unwrap();
        let other_part = super::tests::part(&other.binding);
        let held = BTreeMap::from([(other.binding.locator, other.object.bytes.clone())]);
        let none = Keyring::default();
        assert_eq!(
            read(&held, &none, &BTreeMap::new(), &other_part),
            RecordObject::Refused
        );
        // Without the checkpoint's envelope it waits.
        let unknown = OracleRecords {
            space: SPACE,
            envelopes: &BTreeMap::<EventId, frasil_events::Event>::new(),
            objects: &objects,
            keys: &keys,
            object_keys: &object_keys,
        };
        assert_eq!(
            unknown.record_object(checkpoint, &part),
            RecordObject::Missing
        );
    }

    #[test]
    fn a_record_past_the_bound_is_too_large() {
        assert_eq!(MAX_RECORD_BYTES, 256 << 20);
        let over = vec![0u8; usize::try_from(MAX_RECORD_BYTES).unwrap() + 1];
        assert_eq!(
            seal_record(&SPACE, &K_R, own(), &over),
            Err(ErrorClass::TooLarge)
        );
    }
}
