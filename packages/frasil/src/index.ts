/**
 * Frasil's client for browsers: a device that shares spaces of documents, tables and files, end
 * to end encrypted, online and offline. It keeps its records sealed in the browser's storage and
 * syncs through always-on peers, which hold no key.
 *
 * ```ts
 * import { Device, Storage } from "@frasil/client";
 *
 * const device = await Device.open(Storage.indexedDb("my-app"), unlockKey);
 * const space = await device.createSpace();
 * await device.connect("https://peer.example.org");
 * const note = space.createDocument();
 * await note.edit((doc) => doc.text("body").insert(0, "Hello"));
 * ```
 *
 * @module
 */

export {
  Advanced,
  type BackdatedCheckpointEvent,
  type BadCheckpointEvent,
  type BadStatementEvent,
  type ChangedEvent,
  type CheckpointInEffectEvent,
  type CheckpointPendingEvent,
  type CheckpointPolicy,
  type CheckpointRivalEvent,
  type CheckpointWithheldEvent,
  type Confirm,
  type DelayedEvent,
  type DeliveredEvent,
  type DepositPeerDistrustedEvent,
  type DepositTokens,
  Device,
  type DeviceKeys,
  type ErasedWhileLateEvent,
  type ErasureAwaitingWelcomeEvent,
  type ErasureCannotEraseEvent,
  type ErasureCheckpointEvent,
  type ErasureLateAtPeerEvent,
  type ErasureUnansweredEvent,
  type ErasureVoidEvent,
  type Event,
  Events,
  type GuestTerms,
  type HistoryMode,
  type Ingested,
  Joining,
  JoiningPerson,
  type LateEvent,
  type ListCheckpointPendingEvent,
  type ListCheckpointRivalEvent,
  type ListCheckpointStatus,
  type MemberId,
  type MixedCutEvent,
  type MovedEvent,
  type NeedsLaterVersionEvent,
  type Options,
  Peer,
  type PeerErrorEvent,
  type PeerNeedsVersionEvent,
  type PeerStatus,
  type PendingChangesEvent,
  type PendingListCheckpoint,
  type PersonId,
  PROPOSE_AT_FRAME_BYTES,
  PROPOSE_AT_ROSTER_EVENTS,
  type RankAttemptRefusedEvent,
  type RecoverySheet,
  type RemovedEvent,
  type RequestSignedAgainEvent,
  type RolledBackEvent,
  type SignedHeaders,
  type SlotHeldEvent,
  type SpaceAdmission,
  SpaceFileInvitation,
  type UndeliveredEvent,
  type WithheldEvent,
  type WriteReadyEvent,
} from "./device.js";
export {
  Drive,
  DriveBatch,
  type DriveChange,
  type DriveEntry,
  type DriveFile,
  type EntryId,
  type FileVersion,
  type ReleasedBlob,
} from "./drive.js";
export { type ErrorCode, FrasilError, isOtherRevision, type KnownErrorCode } from "./errors.js";
export { IndexClient } from "./index-client.js";
export {
  type ChangeSource,
  type Observable,
  type ObserveOptions,
  observe,
  type Snapshot,
  type Status,
  structurallyEqual,
} from "./observe.js";
export type { BlobDetails } from "./references.js";
export {
  type DeviceLists,
  type ListEvent,
  type NonceStore,
  type VerifiedRequest,
  verifySignedRequest,
} from "./requests.js";
export { panicMessage } from "./runtime.js";
export {
  type BackdatedCheckpoint,
  type CheckpointId,
  type CheckpointStatus,
  Ephemeral,
  type ImportedSpaceFile,
  type LateChange,
  type LateChangeKind,
  type Level,
  type Member,
  type MemberKind,
  type PendingCheckpoint,
  Space,
  type SpaceChange,
  type SpaceFileExport,
  type SpaceFileHistory,
  type SpaceFileInfo,
  type SpaceFileRoad,
  type SpaceFileSection,
  type SpaceFileWayIn,
  type SpaceId,
  type StreamInfo,
  type StreamKind,
} from "./space.js";
export { type Commit, IndexedDbStore, MemoryStore, Storage, type Store } from "./stores.js";
export {
  type BlobChange,
  type BlobId,
  type BlobInfo,
  type BlobStatus,
  Blobs,
  type Change,
  type ChangeAuthor,
  type ChangeId,
  type DocumentEdit,
  type DocumentValue,
  type LastChange,
  type ListEdit,
  Live,
  LoroDocument,
  type MapEdit,
  type Origin,
  type Progress,
  Receipt,
  type RecordChange,
  Records,
  type Review,
  type ReviewChange,
  type Row,
  type RowChange,
  type RowEntry,
  type RowKey,
  type RowParser,
  type StandardResult,
  type StandardSchemaV1,
  type StreamId,
  type Suggestion,
  type SuggestionId,
  Table,
  type TextEdit,
  type TextStep,
  Transaction,
  type Value,
  type Version,
  type VersionId,
} from "./streams.js";
export { manifestToTypeScript } from "./typed.js";
