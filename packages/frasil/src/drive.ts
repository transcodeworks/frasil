/**
 * Drives (ext-drive.md): folders, files and documents of a space, in one Loro document that every
 * application of the space reads and writes alike. Each change is one change of the document,
 * signed and sealed by this device; concurrent changes merge, moves included. A batch makes several
 * changes as one, all or none.
 *
 * ```ts
 * import { Drive } from "@frasil/client";
 *
 * const drive = await Drive.create(space);
 * const folder = await drive.addFolder(null, "Scripts");
 * await drive.addFile(folder, "draft.pdf", { stream: files.id, blob });
 * await drive.batch((b) => {
 *   const invoices = b.addFolder(null, "Invoices");
 *   b.setMeta(invoices, "example.type", "invoices");
 * });
 * const stop = drive.onChange(({ entries, roots }) => render(entries, roots));
 * ```
 *
 * @module
 */

import { FrasilError } from "./errors.js";
import { asyncSource, type Observable, sharedStore } from "./observe.js";
import { call, callAsync, follow, Handle, type raw } from "./runtime.js";
import type { Space } from "./space.js";
import type {
  BlobId,
  ChangeAuthor,
  DocumentValue,
  Origin,
  Receipt as ReceiptType,
  StreamId,
} from "./streams.js";
import { Receipt } from "./streams.js";

/** An entry's ID in a drive, as 32 hex digits. */
export type EntryId = string;

/** A file entry's blob: its Blobs stream and handle, and what the Blobs entry says of it. */
export interface DriveFile {
  readonly stream: StreamId;
  readonly blob: BlobId;
  /** Its size in bytes, for listings. */
  readonly size?: number;
  /** Its media type, such as `image/png`, for listings. */
  readonly mediaType?: string;
}

/** An entry of a drive. */
export interface DriveEntry {
  readonly id: EntryId;
  /** `folder`, `file`, `document`, or an application's own kind, such as `example.note`. */
  readonly kind: string;
  /** Its own name. */
  readonly name: string;
  /** The name a listing shows: its own, or numbered, as `photo (2).jpg`. */
  readonly shownName: string;
  /** The entry it is in; `null` at the root. */
  readonly parent: EntryId | null;
  /** When it was added, in seconds since 1970 by its writer's clock. */
  readonly added?: number;
  /** When it was last renamed, moved or restored. */
  readonly modified?: number;
  /** When it was sent to the trash itself, while it is there. */
  readonly trashed?: number;
  /** Whether it, or an entry above it, is in the trash. */
  readonly inTrash: boolean;
  /** The applications' own fields. */
  readonly meta: { readonly [key: string]: DocumentValue };
  /** A file's Blobs stream, or a document's stream. */
  readonly stream?: StreamId;
  /** A file's blob. */
  readonly blob?: BlobId;
  /** A file's size in bytes, as the entry says. */
  readonly size?: number;
  /** A file's media type, as the entry says. */
  readonly mediaType?: string;
  /** What a document is, as its application names it. */
  readonly docKind?: string;
  /**
   * A file's heads: its versions that no other version was made from. One is the ordinary case;
   * two or more are a conflict, and each head other than `blob` shows beside the file until a
   * writer resolves it.
   */
  readonly heads?: BlobId[];
}

/**
 * A version of a file: a blob the file has pointed at, recorded with the versions it was made from
 * (ext-drive.md, section 2.4).
 */
export interface FileVersion {
  readonly blob: BlobId;
  /** The Blobs stream of its blob. */
  readonly stream: StreamId;
  /** Its size in bytes, as its record says. */
  readonly size?: number;
  /** When it was written, in seconds since 1970 by its writer's clock. */
  readonly written?: number;
  /** The versions it was made from. */
  readonly parents: BlobId[];
  /**
   * Who wrote it: the device that signed the change that wrote its record, and the person whose
   * list held that device then. Absent when this device does not hold that change.
   */
  readonly author?: ChangeAuthor;
}

/** A blob a purge released: no entry names it any more. */
export interface ReleasedBlob {
  readonly stream: StreamId;
  readonly blob: BlobId;
}

/** A change of a drive, as {@link Drive.onChange} reports it. Read the drive again for what is now. */
export interface DriveChange {
  /** The IDs of the entries it added, changed or removed, sorted. */
  readonly entries: EntryId[];
  /**
   * The names of the document's other root containers it changed, sorted: the records applications
   * keep of the whole drive beside its entries. Never `document`, `entries` or `purged`.
   */
  readonly roots: string[];
  /** Where it was made. */
  readonly origin: Origin;
}

/**
 * Changes made together, lent to a {@link Drive.batch} callback while it runs. Each method makes its
 * change at once, checked against the drive as the changes before it leave it, and throws a
 * refusal, which writes nothing of its own. Once the callback returns, every method throws.
 */
export class DriveBatch {
  #raw: raw.DriveBatch | undefined;

  private constructor(value: raw.DriveBatch) {
    this.#raw = value;
  }

  /** @internal */
  static wrap(value: raw.DriveBatch): DriveBatch {
    return new DriveBatch(value);
  }

  /** @internal Ends the batch once its callback returns. */
  static close(batch: DriveBatch): void {
    const value = batch.#raw;
    batch.#raw = undefined;
    value?.free();
  }

  /** The batch, while its callback runs. */
  get #open(): raw.DriveBatch {
    if (this.#raw === undefined) {
      throw new FrasilError(
        "invalid_input",
        "The batch was written: make its changes before its callback returns.",
      );
    }
    return this.#raw;
  }

  /** As {@link Drive.addFolder}. Returns its ID. */
  addFolder(parent: EntryId | null, name: string): EntryId {
    return call(() => this.#open.addFolder(parent ?? undefined, name));
  }

  /** As {@link Drive.addFile}. Returns its ID. */
  addFile(parent: EntryId | null, name: string, file: DriveFile): EntryId {
    return call(() => this.#open.addFile(parent ?? undefined, name, file));
  }

  /** As {@link Drive.addDocument}. Returns its ID. */
  addDocument(parent: EntryId | null, name: string, stream: StreamId, kind: string): EntryId {
    return call(() => this.#open.addDocument(parent ?? undefined, name, stream, kind));
  }

  /** As {@link Drive.rename}. */
  rename(id: EntryId, name: string): void {
    call(() => this.#open.rename(id, name));
  }

  /** As {@link Drive.moveTo}. */
  moveTo(id: EntryId, parent: EntryId | null): void {
    call(() => this.#open.moveTo(id, parent ?? undefined));
  }

  /** As {@link Drive.moveToTrash}. */
  moveToTrash(id: EntryId): void {
    call(() => this.#open.moveToTrash(id));
  }

  /** As {@link Drive.restore}. */
  restore(id: EntryId): void {
    call(() => this.#open.restore(id));
  }

  /** As {@link Drive.setBlob}. */
  setBlob(id: EntryId, file: DriveFile, parents: readonly BlobId[]): void {
    call(() => this.#open.setBlob(id, file, [...parents]));
  }

  /** As {@link Drive.purge}: the blobs no other entry names, as the batch has left the drive. */
  purge(id: EntryId): ReleasedBlob[] {
    return call(() => this.#open.purge(id) as ReleasedBlob[]);
  }

  /** As {@link Drive.setMeta}. */
  setMeta(id: EntryId, key: string, value: DocumentValue): void {
    call(() => this.#open.setMeta(id, key, value));
  }

  /** As {@link Drive.deleteMeta}. */
  deleteMeta(id: EntryId, key: string): void {
    call(() => this.#open.deleteMeta(id, key));
  }
}

/** A drive: folders, files and documents of a space. From {@link Drive.create} or {@link Drive.open}. */
export class Drive extends Handle<raw.Drive> {
  /** Its space. */
  readonly space: Space;
  readonly #id: StreamId;

  private constructor(value: raw.Drive, space: Space) {
    super(value, "Drive");
    this.space = space;
    this.#id = value.id;
  }

  /** Creates a drive in `space`: a new Loro document that names itself one. */
  static async create(space: Space): Promise<Drive> {
    const value = await callAsync(() => Handle.rawOf(space).createDrive() as Promise<raw.Drive>);
    return new Drive(value, space);
  }

  /** Opens a document of `space` as a drive. Rejects with `invalid_input` if it is not one. */
  static async open(space: Space, id: StreamId): Promise<Drive> {
    const value = await callAsync(() => Handle.rawOf(space).drive(id) as Promise<raw.Drive>);
    return new Drive(value, space);
  }

  /** The drive's document ID in its space. */
  get id(): StreamId {
    return this.#id;
  }

  /** A folder's entries, or the root's, not in the trash themselves, under shown names. */
  entries(folder: EntryId | null = null): Promise<DriveEntry[]> {
    return callAsync(() => this.raw().entries(folder ?? undefined) as Promise<DriveEntry[]>);
  }

  /** Every entry, the trash's included, in order. */
  all(): Promise<DriveEntry[]> {
    return callAsync(() => this.raw().all() as Promise<DriveEntry[]>);
  }

  /** An entry, in the trash or not. */
  entry(id: EntryId): Promise<DriveEntry | undefined> {
    return callAsync(() => this.raw().entry(id) as Promise<DriveEntry | undefined>);
  }

  /** The entry that lists a document stream of the space. */
  entryFor(stream: StreamId): Promise<DriveEntry | undefined> {
    return callAsync(() => this.raw().entryFor(stream) as Promise<DriveEntry | undefined>);
  }

  /** The trash: each entry sent there itself and not inside another, the most recent first. */
  trash(): Promise<DriveEntry[]> {
    return callAsync(() => this.raw().trash() as Promise<DriveEntry[]>);
  }

  /** The files in conflict: two or more heads. An application that reports a drive as settled reports these first. */
  conflicts(): Promise<DriveEntry[]> {
    return callAsync(() => this.raw().conflicts() as Promise<DriveEntry[]>);
  }

  /** A file's versions, oldest first, each with who wrote it. Its heads are the entry's `heads`. */
  versions(id: EntryId): Promise<FileVersion[]> {
    return callAsync(() => this.raw().versions(id) as Promise<FileVersion[]>);
  }

  /**
   * Points a file at a new version: `file`'s blob, put first in a Blobs stream of the space under a
   * new handle, made from `parents`. A save names the version this device's copy came from; a save
   * from a stale copy becomes a second head, a conflict. Naming every head resolves a conflict.
   */
  setBlob(id: EntryId, file: DriveFile, parents: readonly BlobId[]): Promise<void> {
    return callAsync(() => this.raw().setBlob(id, file, [...parents]) as Promise<void>);
  }

  /**
   * Makes an older version of a file its current version again: puts that version's bytes again as
   * a new version made from every head, which also ends a conflict. Every version stays a version.
   * Resolves to the new version's blob. Rejects with `Missing` when no peer or member serves the
   * version's bytes any more.
   */
  restoreVersion(id: EntryId, blob: BlobId): Promise<BlobId> {
    return callAsync(() => this.raw().restoreVersion(id, blob) as Promise<BlobId>);
  }

  /** Adds a folder, the last in `parent`, or at the root for `null`. Resolves to its ID. */
  addFolder(parent: EntryId | null, name: string): Promise<EntryId> {
    return callAsync(() => this.raw().addFolder(parent ?? undefined, name) as Promise<EntryId>);
  }

  /** Adds a file: a blob of a Blobs stream of the space. Resolves to its ID. */
  addFile(parent: EntryId | null, name: string, file: DriveFile): Promise<EntryId> {
    return callAsync(() => this.raw().addFile(parent ?? undefined, name, file) as Promise<EntryId>);
  }

  /**
   * Adds a document: a stream of the space of the application's kind `kind`, such as
   * `example.spreadsheet`. A stream has one entry. Resolves to its ID.
   */
  addDocument(
    parent: EntryId | null,
    name: string,
    stream: StreamId,
    kind: string,
  ): Promise<EntryId> {
    return callAsync(
      () => this.raw().addDocument(parent ?? undefined, name, stream, kind) as Promise<EntryId>,
    );
  }

  /** Renames an entry. */
  rename(id: EntryId, name: string): Promise<void> {
    return callAsync(() => this.raw().rename(id, name) as Promise<void>);
  }

  /** Moves an entry to be the last in `parent`, or at the root for `null`. */
  moveTo(id: EntryId, parent: EntryId | null): Promise<void> {
    return callAsync(() => this.raw().moveTo(id, parent ?? undefined) as Promise<void>);
  }

  /** Sends an entry, with what is inside it, to the trash. */
  moveToTrash(id: EntryId): Promise<void> {
    return callAsync(() => this.raw().moveToTrash(id) as Promise<void>);
  }

  /** Brings back an entry sent to the trash itself, where it was. */
  restore(id: EntryId): Promise<void> {
    return callAsync(() => this.raw().restore(id) as Promise<void>);
  }

  /**
   * Forgets an entry and what is inside it, for good. Resolves to the blobs no other entry names,
   * which the application may remove from their Blobs streams.
   */
  purge(id: EntryId): Promise<ReleasedBlob[]> {
    return callAsync(() => this.raw().purge(id) as Promise<ReleasedBlob[]>);
  }

  /** Sets one of an entry's application fields; name keys with a prefix of your own. */
  setMeta(id: EntryId, key: string, value: DocumentValue): Promise<void> {
    return callAsync(() => this.raw().setMeta(id, key, value) as Promise<void>);
  }

  /** Deletes one of an entry's application fields, if it has it. */
  deleteMeta(id: EntryId, key: string): Promise<void> {
    return callAsync(() => this.raw().deleteMeta(id, key) as Promise<void>);
  }

  /**
   * Makes several changes together, such as a folder with its fields, or a note with its
   * attachments: `changes` makes them on a {@link DriveBatch}, synchronously, and they are written
   * as one change of the document, or none if it throws. Resolves to what it returned; rejects with
   * what it threw, or the write's error. A batch that makes no operation writes nothing.
   *
   * ```ts
   * const folder = await drive.batch((b) => {
   *   const folder = b.addFolder(null, "Invoices");
   *   b.setMeta(folder, "example.type", "invoices");
   *   return folder;
   * });
   * ```
   */
  batch<T>(changes: (batch: DriveBatch) => T): Promise<T> {
    return callAsync(
      () =>
        this.raw().batch((value: raw.DriveBatch) => {
          const batch = DriveBatch.wrap(value);
          try {
            return changes(batch);
          } finally {
            DriveBatch.close(batch);
          }
        }) as Promise<T>,
    );
  }

  /**
   * Makes changes together as {@link Drive.batch} does, and resolves to what `changes` returned
   * with a receipt for the change, or no receipt when the batch made no operation.
   */
  async batchWithReceipt<T>(
    changes: (batch: DriveBatch) => T,
  ): Promise<{ value: T; receipt: ReceiptType | undefined }> {
    const written = (await callAsync(
      () =>
        this.raw().batchWithReceipt((value: raw.DriveBatch) => {
          const batch = DriveBatch.wrap(value);
          try {
            return changes(batch);
          } finally {
            DriveBatch.close(batch);
          }
        }) as Promise<{ value: T; receipt?: raw.Receipt }>,
    )) as { value: T; receipt?: raw.Receipt };
    return {
      value: written.value,
      receipt: written.receipt === undefined ? undefined : Receipt.wrap(written.receipt),
    };
  }

  /**
   * Observes every entry of the drive, as {@link Drive.all} reads them: a store that reads again
   * only after a change of the drive. Asking again returns the same store.
   */
  observe(): Observable<DriveEntry[]> {
    return sharedStore(
      this.space.device,
      `drive\u0000${this.space.id}\u0000${this.id}`,
      () => this.all(),
      asyncSource((wake) => this.onChange(() => wake())),
    );
  }

  /**
   * Calls `callback` with each change from now on, this device's own included: the entries it
   * added, changed or removed, and the document's other root containers it changed, where
   * applications keep records of the whole drive. Resolves to the function that stops it.
   * `onError` gets the error that ends it, if any.
   */
  async onChange(
    callback: (change: DriveChange) => void,
    onError?: (error: unknown) => void,
  ): Promise<() => void> {
    const changes = await callAsync(() => this.raw().changes() as Promise<raw.DriveChanges>);
    return follow<DriveChange>(changes, callback, onError);
  }
}
