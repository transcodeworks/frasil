/**
 * A space's streams, by the adapter that reads them: Loro documents, Records tables and blobs.
 * Each write is one change, signed and sealed by this device.
 *
 * @module
 */

import type { MemberId } from "./device.js";
import { FrasilError } from "./errors.js";
import { asyncSource, identityOf, milliseconds, type Observable, sharedStore } from "./observe.js";
import type { BlobDetails } from "./references.js";
import { call, callAsync, follow, Handle, type raw } from "./runtime.js";
import type { Space } from "./space.js";

/** A stream's ID within its space, as 32 hex digits. */
export type StreamId = string;

/** A blob's ID within its blob stream, as 32 hex digits. */
export type BlobId = string;

/** A suggestion's ID. */
export type SuggestionId = string;

/** A change a suggester proposed, waiting for a writer to accept or dismiss it. */
export interface Suggestion {
  readonly id: SuggestionId;
  /** The member who suggested it. */
  readonly author: MemberId;
  /** The change: a Loro update for a document; for Records, the changeset's CBOR. */
  readonly update: Uint8Array;
}

/** Progress of a blob transfer: bytes done, and the total when known. */
export type Progress = (done: number, total?: number) => void;

/** A change's ID: the unit that carried it, as hex. */
export type ChangeId = string;

/** Where a change was made: by this device, or elsewhere (another member, a peer, or this person's other device). */
export type Origin = "local" | "remote";

/**
 * A change of a Records stream: the rows of one table a write touched, by key, or `"all"` when
 * any row may have changed (a snapshot, a change of who writes, or a feed that fell behind).
 */
export type RecordChange =
  | {
      readonly kind: "rows";
      readonly table: string;
      /** The keys, as text: bytes that are not UTF-8 show with replacement characters. */
      readonly keys: readonly string[];
      /** The keys as written. */
      readonly rawKeys: readonly Uint8Array[];
      readonly origin: Origin;
    }
  | { readonly kind: "all" };

/**
 * A change of a blob stream: a blob put or removed, its bytes arrived whole (`get` reads them
 * now), or a held blob withdrawn because its file changed.
 */
export type BlobChange =
  | { readonly kind: "added" | "removed"; readonly id: BlobId; readonly origin: Origin }
  | { readonly kind: "arrived" | "withdrawn"; readonly id: BlobId };

/**
 * Where a blob's bytes stand on this device: readable, being fetched (`done` of `total` bytes),
 * missing (nothing is sending them now), waiting for keys (the key it is sealed under has not
 * reached this device yet; connecting changes nothing until it does), or withdrawn (a held file
 * changed; peers still have it).
 */
export type BlobStatus =
  | { readonly kind: "readable" }
  | { readonly kind: "fetching"; readonly done: number; readonly total: number }
  | { readonly kind: "missing" }
  | { readonly kind: "keysPending" }
  | { readonly kind: "withdrawn" };

/** A receipt for one write: the change it made, and whether a peer keeps it yet. */
export class Receipt extends Handle<raw.Receipt> {
  readonly #unit: ChangeId;

  private constructor(value: raw.Receipt) {
    super(value, "Receipt");
    this.#unit = value.unit;
  }

  /** @internal */
  static wrap(value: raw.Receipt): Receipt {
    return new Receipt(value);
  }

  /** The change the write made. */
  get unit(): ChangeId {
    return this.#unit;
  }

  /** Whether a peer acknowledged the change. */
  isDurable(): Promise<boolean> {
    return callAsync(() => this.raw().isDurable() as Promise<boolean>);
  }

  /**
   * Waits until a peer acknowledged the change, for at most `withinMs`; rejects with `connection`
   * when none did in time. The change stays on this device, which sends it once it reaches a peer.
   */
  durable(withinMs: number): Promise<void> {
    return callAsync(() => this.raw().durable(milliseconds(withinMs)) as Promise<void>);
  }
}

/** A version's ID: its row's key in the space's versions stream, as hex. */
export type VersionId = string;

/** A named version: a tag a member put on a document's frontier or a table's change. */
export interface Version {
  readonly id: VersionId;
  /** The stream it marks. */
  readonly stream: StreamId;
  /** Its name. Shown, never checked. */
  readonly name: string;
  /**
   * A document's frontier (hex, for {@link LoroDocument.at}), or a table's change (for
   * {@link Records.at}).
   */
  readonly marked: { readonly frontier: string } | { readonly change: ChangeId };
  /** The device that tagged. */
  readonly author: MemberId;
  /** When, by the tagging device's clock, in seconds since 1970. Shown, never checked. */
  readonly time?: number;
}

/** One step of a text change in a review. */
export type TextStep =
  | { readonly retain: number }
  | { readonly insert: string }
  | { readonly delete: number };

/** What a suggestion changes: one entry per container or cell. */
export type ReviewChange =
  | { readonly kind: "text"; readonly container: string; readonly delta: readonly TextStep[] }
  | {
      readonly kind: "map";
      readonly container: string;
      readonly key: string;
      readonly from?: DocumentValue;
      readonly to?: DocumentValue;
    }
  | {
      readonly kind: "list";
      readonly container: string;
      readonly from: readonly DocumentValue[];
      readonly to: readonly DocumentValue[];
    }
  | { readonly kind: "other"; readonly container: string }
  | {
      readonly kind: "cell";
      readonly table: string;
      /** The row's key as text, as {@link Records.rows} shows keys. */
      readonly key: string;
      readonly keyBytes: Uint8Array;
      readonly column: string;
      readonly from?: Value;
      readonly to?: Value;
    };

/** A suggestion read for review: what it changes against the base it was made on. */
export interface Review {
  readonly id: SuggestionId;
  /** The device that suggested it. */
  readonly author: MemberId;
  /** The version a document suggestion was made on (hex), when this device holds it. */
  readonly base?: string;
  /**
   * True when this device lacks what the suggestion depends on: it stays
   * pending, `changes` is empty, and a review after syncing shows it.
   */
  readonly baseMissing: boolean;
  readonly changes: readonly ReviewChange[];
}

/** Who made a change, as the roster names them. */
export interface ChangeAuthor {
  /** The device that signed the change. */
  readonly device: MemberId;
  /** The device's name in the roster, when the roster grants it directly. Shown, never checked. */
  readonly deviceName?: string;
  /** The person whose device list vouches for the device, when it reaches the space through one. */
  readonly person?: MemberId;
  /** The person's name in the roster. Shown, never checked. */
  readonly personName?: string;
  /** Every person whose list held the device at the change's place; `person` is the first. */
  readonly persons: readonly MemberId[];
}

/** What a change did to a row of a table. */
export interface RowChange {
  readonly table: string;
  /** The row's key as text, as {@link Records.rows} and {@link Records.at} show keys. */
  readonly key: string;
  /** The row's key as written. */
  readonly keyBytes: Uint8Array;
  /** The columns it set or cleared. */
  readonly columns: readonly string[];
  readonly inserted: boolean;
  readonly deleted: boolean;
}

/**
 * One change of a document's or a table's history: the unit that carried it, with its author from
 * the signature and the roster. Changes come oldest first, in the space's canonical order.
 */
export interface Change {
  readonly id: ChangeId;
  readonly author: ChangeAuthor;
  /** The change's place in its writer's chain, and its height in the space's log. */
  readonly seq: number;
  readonly height: number;
  /** When, as the writer's own clock recorded it, in seconds since 1970; a document change only. */
  readonly time?: number;
  readonly kind: "edit" | "suggestion" | "review" | "snapshot" | "other";
  /** Where a suggestion stands. */
  readonly standing?: "open" | "accepted" | "dismissed";
  /** The suggestions a review accepts and dismisses. */
  readonly accepts?: readonly SuggestionId[];
  readonly dismisses?: readonly SuggestionId[];
  /** What became of it at this device. */
  readonly effect: "applied" | "waiting" | "refused" | "withdrawn";
  /** The class a waiting or refused change waits or was refused under. */
  readonly class?: string;
  /** A document change's operations: one peer's counter range. The peer is a decimal string. */
  readonly span?: { readonly peer: string; readonly from: number; readonly to: number };
  /** The version just before a document change, and the version with it: hex, for {@link LoroDocument.at}. */
  readonly before?: string;
  readonly after?: string;
  /** The containers a document change changed, as Loro names them. */
  readonly containers?: readonly string[];
  /** The rows a table change wrote. */
  readonly rows?: readonly RowChange[];
}

// ---- Documents --------------------------------------------------------------------------------

/**
 * A value in a Loro document: `null`, a boolean, a number (a `bigint` beyond 2^53), a string, a
 * `Uint8Array`, an array of values, or a plain object of values.
 */
export type DocumentValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | readonly DocumentValue[]
  | { readonly [key: string]: DocumentValue };

/** Edits to a text container. Positions and lengths count UTF-16 code units, as strings do. */
export interface TextEdit {
  insert(index: number, text: string): TextEdit;
  delete(index: number, length: number): TextEdit;
}

/** Edits to a map container. */
export interface MapEdit {
  set(key: string, value: DocumentValue): MapEdit;
  delete(key: string): MapEdit;
}

/** Edits to a list container. */
export interface ListEdit {
  insert(index: number, value: DocumentValue): ListEdit;
  delete(index: number, length: number): ListEdit;
}

/** How {@link LoroDocument.setText} compares. */
export interface SetTextOptions {
  /** How long the comparison may take, in milliseconds: two seconds if not given. */
  readonly limitMs?: number;
  /**
   * Fails at the limit (`limit_passed`), the document as it was, rather than replacing the changed
   * part.
   */
  readonly stopAtLimit?: boolean;
}

/** What {@link LoroDocument.setText} did. */
export interface TextWritten {
  /** Nothing to write, small edits, or the changed part replaced in one operation. */
  readonly outcome: "unchanged" | "edited" | "replaced";
  /** How many units it took: a replica shows the change once it holds them all. */
  readonly units: number;
  /** Whether another change arrived during the comparison: the document holds both. */
  readonly moved: boolean;
  /** Whether the time limit passed. */
  readonly limitPassed: boolean;
}

/** What {@link LoroDocument.edit}'s callback edits: the document's root containers, by name. */
export interface DocumentEdit {
  text(container: string): TextEdit;
  map(container: string): MapEdit;
  list(container: string): ListEdit;
}

type Op = Record<string, unknown>;

function documentEdit(ops: Op[]): DocumentEdit {
  return {
    text(container) {
      const text: TextEdit = {
        insert(index, insert) {
          ops.push({ op: "textInsert", container, index, text: insert });
          return text;
        },
        delete(index, length) {
          ops.push({ op: "textDelete", container, index, length });
          return text;
        },
      };
      return text;
    },
    map(container) {
      const map: MapEdit = {
        set(key, value) {
          ops.push({ op: "mapSet", container, key, value });
          return map;
        },
        delete(key) {
          ops.push({ op: "mapDelete", container, key });
          return map;
        },
      };
      return map;
    },
    list(container) {
      const list: ListEdit = {
        insert(index, value) {
          ops.push({ op: "listInsert", container, index, value });
          return list;
        },
        delete(index, length) {
          ops.push({ op: "listDelete", container, index, length });
          return list;
        },
      };
      return list;
    },
  };
}

/**
 * A Loro document in a space. Each edit is one change; every member's edits merge.
 *
 * The Rust crate names it `frasil::Document`; here it is `LoroDocument`, so that importing it
 * does not shadow the DOM's global `Document`.
 */
export class LoroDocument extends Handle<raw.Document> {
  /** Its space. */
  readonly space: Space;
  readonly #id: StreamId;

  private constructor(value: raw.Document, space: Space) {
    super(value, "LoroDocument");
    this.space = space;
    this.#id = value.id;
  }

  /** @internal */
  static wrap(value: raw.Document, space: Space): LoroDocument {
    return new LoroDocument(value, space);
  }

  /** The document's ID in its space. */
  get id(): StreamId {
    return this.#id;
  }

  /**
   * Edits the document: what `edit` does to its containers is written as one change. Nothing is
   * written when `edit` throws, makes no operation, or an operation fails.
   *
   * ```ts
   * await note.edit((doc) => doc.text("body").insert(0, "Hello"));
   * ```
   */
  async edit(edit: (doc: DocumentEdit) => void): Promise<void> {
    const ops: Op[] = [];
    edit(documentEdit(ops));
    await callAsync(() => this.raw().edit(ops) as Promise<void>);
  }

  /** Edits the document as {@link LoroDocument.edit} does, and resolves to a receipt for the change. */
  async editWithReceipt(edit: (doc: DocumentEdit) => void): Promise<Receipt> {
    const ops: Op[] = [];
    edit(documentEdit(ops));
    return Receipt.wrap(
      await callAsync(() => this.raw().editWithReceipt(ops) as Promise<raw.Receipt>),
    );
  }

  /**
   * Observes a read of the document: `read` runs on its containers' values once the store has a
   * subscriber, then again after each change of the document, or of keys that let its changes
   * read, and subscribers hear of each result that differs. Asking again with the same `read`
   * returns the same store, so keep `read` stable, such as a function defined outside a
   * component.
   *
   * ```ts
   * const title = (doc: { [container: string]: DocumentValue }) => String(doc.title ?? "");
   * const store = note.observe(title);
   * ```
   */
  observe<T>(read: (doc: { [container: string]: DocumentValue }) => T): Observable<T> {
    const id = this.#id;
    return sharedStore(
      this.space.device,
      `doc\u0000${this.space.id}\u0000${id}\u0000${identityOf(read)}`,
      async () => read(await this.read()),
      (wake, fail) =>
        this.space.onChange((change) => {
          if (change.members || change.spaceEvents || change.streams.includes(id)) wake();
        }, fail),
    );
  }

  /**
   * Sets a text container to `text`, writing only what differs: an edit within a line stays small
   * and merges with another writer's. When most of it changed, or the time limit passes, the
   * changed part is replaced in one operation. A change arriving meanwhile is not overwritten: the
   * two merge, and `moved` says so. The comparison runs on the page's own thread.
   *
   * A change in several units commits each on its own. A failure after the first, such as the
   * store's (`store`), can leave some written and syncing: the text stays as it was everywhere,
   * those units stay pending for good and show in history, and calling again writes the change
   * anew.
   *
   * ```ts
   * await note.setText("body", edited, { limitMs: 500 });
   * ```
   */
  setText(container: string, text: string, options: SetTextOptions = {}): Promise<TextWritten> {
    return callAsync(
      () =>
        this.raw().setText(
          container,
          text,
          options.limitMs,
          options.stopAtLimit ?? false,
        ) as Promise<TextWritten>,
    );
  }

  /** The text of one of the document's text containers: empty before its first change. */
  text(container: string): Promise<string> {
    return callAsync(() => this.raw().text(container) as Promise<string>);
  }

  /** The whole document as this device holds it: each root container's value, by name. */
  read(): Promise<{ [container: string]: DocumentValue }> {
    return callAsync(() => this.raw().read() as Promise<{ [container: string]: DocumentValue }>);
  }

  /**
   * Moves the document into `restricted`, a restricted space of its space
   * ({@link Space.createRestricted}): the new document starts from this one's current state, and
   * this one ends. Resolves to the new document.
   */
  async moveTo(restricted: Space): Promise<LoroDocument> {
    const moved = await callAsync(
      () => this.raw().moveTo(Handle.rawOf(restricted)) as Promise<raw.Document>,
    );
    return LoroDocument.wrap(moved, restricted);
  }

  /**
   * Live editing with the application's own `LoroDoc`: set its peer to {@link Live.peerId}, commit
   * its local updates with {@link Live.commit}, and import what {@link Live.onChange} delivers.
   */
  async live(): Promise<Live> {
    return Live.wrap(await callAsync(() => this.raw().live() as Promise<raw.Live>));
  }

  /**
   * Suggests a Loro update for a writer to accept. Make the update on a fork of the document, not
   * in the application's live `LoroDoc`. Resolves to its ID.
   */
  suggest(update: Uint8Array): Promise<SuggestionId> {
    return callAsync(() => this.raw().suggest(update) as Promise<SuggestionId>);
  }

  /** The suggestions waiting on the document. */
  suggestions(): Promise<Suggestion[]> {
    return callAsync(() => this.raw().suggestions() as Promise<Suggestion[]>);
  }

  /** Accepts suggestions: each becomes a change of this device. */
  accept(ids: readonly SuggestionId[]): Promise<void> {
    return callAsync(() => this.raw().accept([...ids]) as Promise<void>);
  }

  /** Dismisses suggestions. */
  dismiss(ids: readonly SuggestionId[]): Promise<void> {
    return callAsync(() => this.raw().dismiss([...ids]) as Promise<void>);
  }

  /**
   * The document's history: one change per unit this device holds of it, oldest first, with who
   * made it as the roster names them, its span, and the versions before and after it.
   */
  history(): Promise<Change[]> {
    return callAsync(() => this.raw().history() as Promise<Change[]>);
  }

  /**
   * The document as it stood at a version (a change's `before` or `after`): a snapshot's bytes, to
   * import into a `LoroDoc` of the page's own. A read-only view: the document itself is Frasil's.
   */
  at(version: string): Promise<Uint8Array> {
    return callAsync(() => this.raw().at(version) as Promise<Uint8Array>);
  }

  /** Tags the document as it stands, by name: a synced version every member sees. */
  tag(name: string): Promise<Version> {
    return callAsync(() => this.raw().tag(name) as Promise<Version>);
  }

  /** The versions tagged on the document. */
  versions(): Promise<Version[]> {
    return callAsync(() => this.raw().versions() as Promise<Version[]>);
  }

  /** Reads a suggestion for review: what it changes against the version it was made on. */
  review(id: SuggestionId): Promise<Review> {
    return callAsync(() => this.raw().review(id) as Promise<Review>);
  }
}

/** Live editing of a document, from {@link LoroDocument.live}. */
export class Live extends Handle<raw.Live> {
  readonly #peerId: bigint;

  private constructor(value: raw.Live) {
    super(value, "Live");
    this.#peerId = value.peerId;
  }

  /** @internal */
  static wrap(value: raw.Live): Live {
    return new Live(value);
  }

  /** The peer ID to set on the application's own `LoroDoc` (`doc.setPeerId(live.peerId)`). */
  get peerId(): bigint {
    return this.#peerId;
  }

  /** Commits a Loro update that the application's `LoroDoc` made as {@link Live.peerId}. */
  commit(update: Uint8Array): Promise<void> {
    return callAsync(() => this.raw().commit(update) as Promise<void>);
  }

  /** Suggests a Loro update for a writer to accept, instead of committing it. */
  suggest(update: Uint8Array): Promise<void> {
    return callAsync(() => this.raw().suggest(update) as Promise<void>);
  }

  /**
   * The updates since `version`, an encoded Loro version vector; with none, a Loro snapshot of the
   * whole document, to import into a fresh `LoroDoc`.
   */
  exportSince(version: Uint8Array = new Uint8Array()): Uint8Array {
    return call(() => this.raw().exportSince(version));
  }

  /** The document's version, an encoded Loro version vector. */
  version(): Uint8Array {
    return call(() => this.raw().version());
  }

  /**
   * Calls `callback` with each Loro update others make from now on, to import into the
   * application's `LoroDoc`. Returns the function that stops it. `onError` gets the error that
   * ends it, if any.
   */
  onChange(callback: (update: Uint8Array) => void, onError?: (error: unknown) => void): () => void {
    return follow<Uint8Array>(
      call(() => this.raw().changes()),
      callback,
      onError,
    );
  }
}

// ---- Records ----------------------------------------------------------------------------------

/**
 * A cell's value: an integer (a `bigint` beyond 2^53), a float (a `number` with a fraction; never
 * NaN), a boolean, a `Uint8Array`, a string, an array of values, or a `Map` from non-negative
 * integers to values. A `number` without a fraction is stored as an integer.
 */
export type Value =
  | number
  | bigint
  | boolean
  | string
  | Uint8Array
  | readonly Value[]
  | ReadonlyMap<number | bigint, Value>;

/** Who changed a row last, and when they say they did. */
export interface LastChange {
  /** The device that wrote the row's latest cell. */
  readonly author: MemberId;
  /** The change that wrote it. */
  readonly change: string;
  /**
   * The writer's wall clock when it wrote, in seconds since 1970-01-01T00:00:00Z, if it recorded
   * one. It is the writer's claim, which no device checks: show it as the writer's own.
   */
  readonly time?: number;
}

/** A row: its columns' values. A cleared column is absent. */
export type Row = { readonly [column: string]: Value };

/** A row's key: a string, as its UTF-8 bytes, or bytes. */
export type RowKey = string | Uint8Array;

/** The cells one write changes, as one change. */
export class Transaction {
  /** @internal */
  readonly ops: Op[] = [];

  /** Inserts a row, or keeps it: a row shows once inserted. */
  insert(table: string, key: RowKey): this {
    this.ops.push({ op: "insert", table, key });
    return this;
  }

  /** Sets a cell. */
  set(table: string, key: RowKey, column: string, value: Value): this {
    this.ops.push({ op: "set", table, key, column, value });
    return this;
  }

  /** Clears a cell. */
  clear(table: string, key: RowKey, column: string): this {
    this.ops.push({ op: "clear", table, key, column });
    return this;
  }

  /** Deletes a row. */
  delete(table: string, key: RowKey): this {
    this.ops.push({ op: "delete", table, key });
    return this;
  }
}

const utf8 = new TextDecoder();
const utf8Encoder = new TextEncoder();

/** A key's bytes. */
function keyBytes(key: RowKey): Uint8Array {
  return typeof key === "string" ? utf8Encoder.encode(key) : key;
}

/** Whether two byte strings are the same. */
function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

/** Bytes as lowercase hex, for keys of shared stores. */
function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** A row with its key, from {@link Records.rowsRange}. */
export interface RowEntry {
  /** The key as text: bytes that are not UTF-8 show with replacement characters. */
  readonly key: string;
  /** The key as written: pass it as `after` for the next page. */
  readonly rawKey: Uint8Array;
  readonly row: Row;
}

/**
 * A validator in the Standard Schema form (https://standardschema.dev), as Zod, Valibot, ArkType
 * and others give: what {@link Records.table} checks each row with.
 */
export interface StandardSchemaV1<Input = unknown, Output = Input> {
  readonly "~standard": {
    readonly version: 1;
    readonly vendor: string;
    readonly validate: (value: unknown) => StandardResult<Output> | Promise<StandardResult<Output>>;
    readonly types?: { readonly input: Input; readonly output: Output } | undefined;
  };
}

/** What a Standard Schema validator returns. */
export type StandardResult<Output> =
  | { readonly value: Output; readonly issues?: undefined }
  | { readonly issues: ReadonlyArray<{ readonly message: string }> };

/** How {@link Records.table} reads a row: a Standard Schema validator, or a function. */
export type RowParser<T> = StandardSchemaV1<Row, T> | ((row: Row) => T);

/** A raw change, as the module gives it. */
type RawRecordChange =
  | { kind: "rows"; table: string; keys: Uint8Array[]; origin: Origin }
  | { kind: "all" };

/** A listener of a shared feed. */
interface Listener<T> {
  readonly callback: (item: T) => void;
  readonly onError: ((error: unknown) => void) | undefined;
}

/**
 * One feed shared by every listener of the same stream on a device: started for the first, stopped
 * after the last, so that a hundred observed rows decode each change once.
 */
class SharedFeed<T> {
  readonly #listeners = new Set<Listener<T>>();
  readonly #start: (emit: (item: T) => void, fail: (error: unknown) => void) => () => void;
  readonly #done: () => void;
  #stop: (() => void) | undefined;

  constructor(
    start: (emit: (item: T) => void, fail: (error: unknown) => void) => () => void,
    done: () => void,
  ) {
    this.#start = start;
    this.#done = done;
  }

  add(callback: (item: T) => void, onError?: (error: unknown) => void): () => void {
    const listener: Listener<T> = { callback, onError };
    this.#listeners.add(listener);
    if (this.#stop === undefined) {
      this.#stop = this.#start(
        (item) => {
          for (const each of [...this.#listeners]) each.callback(item);
        },
        (error) => {
          const ended = [...this.#listeners];
          this.#listeners.clear();
          this.#stop = undefined;
          this.#done();
          for (const each of ended) each.onError?.(error);
        },
      );
    }
    let listening = true;
    return () => {
      if (!listening) return;
      listening = false;
      this.#listeners.delete(listener);
      if (this.#listeners.size === 0) {
        this.#stop?.();
        this.#stop = undefined;
        this.#done();
      }
    };
  }
}

/** The shared feeds of Records streams, by device, then space and stream. */
const recordFeeds = new WeakMap<object, Map<string, SharedFeed<RecordChange>>>();

/** The shared feed of a Records stream. */
function feedOf(records: Records): SharedFeed<RecordChange> {
  const device = records.space.device;
  let feeds = recordFeeds.get(device);
  if (feeds === undefined) {
    feeds = new Map();
    recordFeeds.set(device, feeds);
  }
  const key = `${records.space.id}\u0000${records.id}`;
  let feed = feeds.get(key);
  if (feed === undefined) {
    const made: SharedFeed<RecordChange> = new SharedFeed(
      (emit, fail) => records.startFeed(emit, fail),
      () => {
        if (feeds.get(key) === made) feeds.delete(key);
      },
    );
    feeds.set(key, made);
    feed = made;
  }
  return feed;
}

/**
 * One table of a Records stream, its rows read as `T`: by a validator, or as they are. From
 * {@link Records.table}.
 *
 * ```ts
 * interface Task { title: string; done?: boolean }
 * const tasks = records.table<Task>("tasks", TaskSchema);
 * const all = await tasks.rows(); // Map<string, Task>
 * ```
 */
export class Table<T> {
  /** The stream it is a table of. */
  readonly records: Records;
  /** Its name. */
  readonly name: string;
  readonly #parse: (row: Row) => Promise<T>;
  /** What names the validator in the keys of shared stores. */
  readonly #identity: number;

  /** @internal */
  constructor(records: Records, name: string, parse?: RowParser<T>) {
    this.records = records;
    this.name = name;
    this.#parse = parserOf(name, parse);
    this.#identity = identityOf(parse);
  }

  /** The rows, by key, in key order, each read as `T`; rejects when one does not read. */
  async rows(): Promise<Map<string, T>> {
    const rows = await this.records.rows(this.name);
    const out = new Map<string, T>();
    for (const [key, row] of rows) out.set(key, await this.#parse(row));
    return out;
  }

  /** One row, if it shows, read as `T`. */
  async row(key: RowKey): Promise<T | undefined> {
    const row = await this.records.row(this.name, key);
    return row === undefined ? undefined : this.#parse(row);
  }

  /**
   * Observes the rows, as {@link Table.rows} reads them. Asking again for the same table with the
   * same validator returns the same store, so it may be asked for during a render.
   */
  observeRows(): Observable<Map<string, T>> {
    const records = this.records;
    return sharedStore(
      records.space.device,
      `table\u0000${records.space.id}\u0000${records.id}\u0000${this.name}\u0000${this.#identity}`,
      () => this.rows(),
      (wake, fail) =>
        records.onChange((change) => {
          if (change.kind === "all" || change.table === this.name) wake();
        }, fail),
    );
  }

  /** Observes one row, as {@link Table.row} reads it. Shared, as {@link Table.observeRows} is. */
  observeRow(key: RowKey): Observable<T | undefined> {
    const records = this.records;
    const bytes = keyBytes(key);
    return sharedStore(
      records.space.device,
      `table-row\u0000${records.space.id}\u0000${records.id}\u0000${this.name}\u0000${this.#identity}\u0000${hexOf(bytes)}`,
      () => this.row(bytes),
      (wake, fail) =>
        records.onChange((change) => {
          if (
            change.kind === "all" ||
            (change.table === this.name && change.rawKeys.some((k) => sameBytes(k, bytes)))
          ) {
            wake();
          }
        }, fail),
    );
  }
}

/** The function that reads a row of `table` as `T`. */
function parserOf<T>(table: string, parse?: RowParser<T>): (row: Row) => Promise<T> {
  if (parse === undefined) return async (row) => row as unknown as T;
  if (typeof parse === "function") return async (row) => parse(row);
  return async (row) => {
    const result = await parse["~standard"].validate(row);
    if (result.issues !== undefined) {
      const issues = result.issues.map((issue) => issue.message).join("; ");
      throw new FrasilError("invalid_input", `A row of ${table} does not read: ${issues}`);
    }
    return result.value;
  };
}

/** Tables of rows in a space. Each write is one change; for each cell, the latest write wins. */
export class Records extends Handle<raw.Records> {
  /** Its space. */
  readonly space: Space;
  readonly #id: StreamId;

  private constructor(value: raw.Records, space: Space) {
    super(value, "Records");
    this.space = space;
    this.#id = value.id;
  }

  /** @internal */
  static wrap(value: raw.Records, space: Space): Records {
    return new Records(value, space);
  }

  /** The stream's ID in its space. */
  get id(): StreamId {
    return this.#id;
  }

  /**
   * Calls `callback` with each change of the tables from now on, this device's own writes
   * included: the rows of one table a write touched, or `"all"` when any row may have changed.
   * Returns the function that stops it. `onError` gets the error that ends it, if any.
   */
  onChange(
    callback: (change: RecordChange) => void,
    onError?: (error: unknown) => void,
  ): () => void {
    return feedOf(this).add(callback, onError);
  }

  /** @internal The stream's one feed, started for its first listener. */
  startFeed(emit: (change: RecordChange) => void, fail: (error: unknown) => void): () => void {
    return follow<RawRecordChange>(
      call(() => this.raw().changes()),
      (change) =>
        emit(
          change.kind === "rows"
            ? {
                kind: "rows",
                table: change.table,
                keys: change.keys.map((key) => utf8.decode(key)),
                rawKeys: change.keys,
                origin: change.origin,
              }
            : { kind: "all" },
        ),
      fail,
    );
  }

  /**
   * Observes a table's rows, as {@link Records.rows} reads them: a store that reads again only
   * after a change of this table. Asking again for the same table returns the same store.
   */
  observeRows(table: string): Observable<Map<string, Row>> {
    return sharedStore(
      this.space.device,
      `rows\u0000${this.space.id}\u0000${this.#id}\u0000${table}`,
      () => this.rows(table),
      (wake, fail) =>
        this.onChange((change) => {
          if (change.kind === "all" || change.table === table) wake();
        }, fail),
    );
  }

  /**
   * Observes one row, as {@link Records.row} reads it: `undefined` while it does not show. It
   * reads again only after a write to that row. Asking again for the same row returns the same
   * store.
   */
  observeRow(table: string, key: RowKey): Observable<Row | undefined> {
    const bytes = keyBytes(key);
    return sharedStore(
      this.space.device,
      `row\u0000${this.space.id}\u0000${this.#id}\u0000${table}\u0000${hexOf(bytes)}`,
      () => this.row(table, bytes),
      (wake, fail) =>
        this.onChange((change) => {
          if (
            change.kind === "all" ||
            (change.table === table && change.rawKeys.some((k) => sameBytes(k, bytes)))
          ) {
            wake();
          }
        }, fail),
    );
  }

  /**
   * At most `limit` rows of a table, in key order, from the first key after `after` (from the
   * first key when it is not given). Pass the last row's `rawKey` as `after` for the next page.
   */
  async rowsRange(table: string, options: { after?: RowKey; limit: number }): Promise<RowEntry[]> {
    const rows = await callAsync(
      () =>
        this.raw().rowsRange(table, options.after, options.limit) as Promise<[Uint8Array, Row][]>,
    );
    return rows.map(([rawKey, row]) => ({ key: utf8.decode(rawKey), rawKey, row }));
  }

  /** The rows of a table whose keys start with `prefix`, by key, in key order. */
  async rowsWithPrefix(table: string, prefix: RowKey): Promise<Map<string, Row>> {
    const rows = await callAsync(
      () => this.raw().rowsWithPrefix(table, prefix) as Promise<[Uint8Array, Row][]>,
    );
    return new Map(rows.map(([key, row]) => [utf8.decode(key), row]));
  }

  /** Writes the cells `write` sets, as one change, and resolves to a receipt for it. */
  async writeWithReceipt(write: (transaction: Transaction) => void): Promise<Receipt> {
    const transaction = new Transaction();
    write(transaction);
    return Receipt.wrap(
      await callAsync(() => this.raw().writeWithReceipt(transaction.ops) as Promise<raw.Receipt>),
    );
  }

  /**
   * One table, its rows read as `T`: checked by a Standard Schema validator (Zod, Valibot,
   * ArkType, …) or a function, or taken as they are when none is given.
   */
  table<T = Row>(name: string, parse?: RowParser<T>): Table<T> {
    return new Table(this, name, parse);
  }

  /**
   * Writes the cells `write` sets, as one change.
   *
   * ```ts
   * await tasks.write((tx) => tx.insert("tasks", "t1").set("tasks", "t1", "title", "Call Ana"));
   * ```
   */
  async write(write: (transaction: Transaction) => void): Promise<void> {
    const transaction = new Transaction();
    write(transaction);
    await callAsync(() => this.raw().write(transaction.ops) as Promise<void>);
  }

  /**
   * The rows of a table, by key, in key order. Keys show as text: a key written as bytes that are
   * not UTF-8 shows with replacement characters.
   */
  async rows(table: string): Promise<Map<string, Row>> {
    const rows = await callAsync(() => this.raw().rows(table) as Promise<[Uint8Array, Row][]>);
    return new Map(rows.map(([key, row]) => [utf8.decode(key), row]));
  }

  /** One row of a table, if it shows. */
  row(table: string, key: RowKey): Promise<Row | undefined> {
    return callAsync(() => this.raw().row(table, key) as Promise<Row | undefined>);
  }

  /**
   * Who changed a row last, in which change, and when the writer says it did: the row's cell with
   * the greatest stamp, its marker included; `undefined` while no cell of the row is written.
   */
  lastChange(table: string, key: RowKey): Promise<LastChange | undefined> {
    return callAsync(() => this.raw().lastChange(table, key) as Promise<LastChange | undefined>);
  }

  /** Suggests the cells `write` sets, as one change, for a writer to accept. */
  async suggest(write: (transaction: Transaction) => void): Promise<void> {
    const transaction = new Transaction();
    write(transaction);
    await callAsync(() => this.raw().suggest(transaction.ops) as Promise<void>);
  }

  /** The suggestions waiting on the tables. */
  suggestions(): Promise<Suggestion[]> {
    return callAsync(() => this.raw().suggestions() as Promise<Suggestion[]>);
  }

  /** Accepts suggestions: each becomes a change of this device. */
  accept(ids: readonly SuggestionId[]): Promise<void> {
    return callAsync(() => this.raw().accept([...ids]) as Promise<void>);
  }

  /** Dismisses suggestions. */
  dismiss(ids: readonly SuggestionId[]): Promise<void> {
    return callAsync(() => this.raw().dismiss([...ids]) as Promise<void>);
  }

  /**
   * The tables' history: one change per unit this device holds of the stream, oldest first, with
   * who made it as the roster names them and the rows and columns it wrote.
   */
  history(): Promise<Change[]> {
    return callAsync(() => this.raw().history() as Promise<Change[]>);
  }

  /**
   * The tables as they stood after a change: a replay of the units up to it, so that "from what"
   * is the row at the change before. Each table's rows by key, keys shown as text.
   */
  async at(change: ChangeId): Promise<Map<string, Map<string, Row>>> {
    const tables = await callAsync(
      () => this.raw().at(change) as Promise<{ [table: string]: [Uint8Array, Row][] }>,
    );
    return new Map(
      Object.entries(tables).map(([table, rows]) => [
        table,
        new Map(rows.map(([key, row]) => [utf8.decode(key), row])),
      ]),
    );
  }

  /** Tags the tables as they stand, by name: a synced version every member sees. */
  tag(name: string): Promise<Version> {
    return callAsync(() => this.raw().tag(name) as Promise<Version>);
  }

  /** The versions tagged on the tables. */
  versions(): Promise<Version[]> {
    return callAsync(() => this.raw().versions() as Promise<Version[]>);
  }

  /** Reads a suggestion for review: each cell it sets, with its value now and the one suggested. */
  review(id: SuggestionId): Promise<Review> {
    return callAsync(() => this.raw().review(id) as Promise<Review>);
  }
}

// ---- Blobs ------------------------------------------------------------------------------------

/** A blob a blob stream holds. */
export interface BlobInfo {
  readonly id: BlobId;
  /** Its name, if it was given one. */
  readonly name?: string;
  /** Its size in bytes. */
  readonly size: number;
}

/** Blobs in a space: files and other bytes, each sealed as an object, which peers keep. */
export class Blobs extends Handle<raw.Blobs> {
  /** Its space. */
  readonly space: Space;
  readonly #id: StreamId;

  private constructor(value: raw.Blobs, space: Space) {
    super(value, "Blobs");
    this.space = space;
    this.#id = value.id;
  }

  /** @internal */
  static wrap(value: raw.Blobs, space: Space): Blobs {
    return new Blobs(value, space);
  }

  /** The stream's ID in its space. */
  get id(): StreamId {
    return this.#id;
  }

  /**
   * Calls `callback` with each change of the stream from now on: a blob put or removed (this
   * device's own included), its bytes arrived, or a held blob withdrawn. Resolves to the function
   * that stops it. `onError` gets the error that ends it, if any.
   */
  async onChange(
    callback: (change: BlobChange) => void,
    onError?: (error: unknown) => void,
  ): Promise<() => void> {
    const changes = await callAsync(() => this.raw().changes() as Promise<raw.BlobChanges>);
    return follow<BlobChange>(changes, callback, onError);
  }

  /** Where a blob's bytes stand on this device: readable, fetching, missing or withdrawn. */
  status(id: BlobId): Promise<BlobStatus> {
    return callAsync(() => this.raw().status(id) as Promise<BlobStatus>);
  }

  /**
   * `length` bytes of a blob from byte `offset`, fewer at its end; `undefined` while this device
   * does not hold it whole. Only the chunks that hold the range are opened, once the blob was
   * read whole on this device since it opened; the first range read opens it whole once, without
   * keeping it, so that every check runs.
   */
  getRange(id: BlobId, offset: number, length: number): Promise<Uint8Array | undefined> {
    return callAsync(
      () => this.raw().getRange(id, offset, length) as Promise<Uint8Array | undefined>,
    );
  }

  /**
   * A blob's bytes, once this device holds them whole: at once if it does, else as soon as they
   * arrive, for at most `withinMs`; rejects with `timeout` when they have not arrived in time.
   */
  getWhenAvailable(id: BlobId, withinMs: number): Promise<Uint8Array> {
    return callAsync(
      () => this.raw().getWhenAvailable(id, milliseconds(withinMs)) as Promise<Uint8Array>,
    );
  }

  /** Observes the blobs the stream holds, as {@link Blobs.list} reads them. Shared, as stores are. */
  observeList(): Observable<BlobInfo[]> {
    return sharedStore(
      this.space.device,
      `blobs\u0000${this.space.id}\u0000${this.#id}`,
      () => this.list(),
      asyncSource((wake) =>
        this.onChange((change) => {
          if (change.kind === "added" || change.kind === "removed") wake();
        }),
      ),
    );
  }

  /**
   * Observes a blob's {@link Blobs.status}: it changes as its bytes arrive or are withdrawn, and,
   * while they are being fetched, as they come. Shared, as stores are.
   */
  observeStatus(id: BlobId): Observable<BlobStatus> {
    let poke: (() => void) | undefined;
    return sharedStore(
      this.space.device,
      `blob\u0000${this.space.id}\u0000${this.#id}\u0000${id}`,
      async () => {
        const status = await this.status(id);
        if (status.kind === "fetching") setTimeout(() => poke?.(), 250);
        return status;
      },
      (wake, fail) => {
        poke = wake;
        const stop = asyncSource((wake) =>
          this.onChange((change) => {
            if (change.id === id) wake();
          }),
        )(wake, fail);
        return () => {
          poke = undefined;
          stop();
        };
      },
    );
  }

  /**
   * The SHA-256 of a blob's plaintext, a stable hash of its content for keying media or comparing
   * with local files; `undefined` while this device cannot read the blob whole. It fetches nothing,
   * and is computed on this device: peers never see it.
   */
  contentHash(id: BlobId): Promise<Uint8Array | undefined> {
    return callAsync(() => this.raw().contentHash(id) as Promise<Uint8Array | undefined>);
  }

  /** Puts a blob, with a name if given. Resolves to its ID. */
  put(bytes: Uint8Array, options: { name?: string } = {}): Promise<BlobId> {
    return callAsync(() => this.raw().put(options.name, bytes) as Promise<BlobId>);
  }

  /** The blobs the stream holds. */
  list(): Promise<BlobInfo[]> {
    return callAsync(() => this.raw().list() as Promise<BlobInfo[]>);
  }

  /**
   * Puts a blob from a stream, with a name if given. The source is read as a stream, but the
   * object is sealed in memory: the whole blob, its sealed chunks and its stored bytes are held
   * at once, so the largest blob a browser can put is bounded by its WebAssembly memory.
   * `onProgress` reports the bytes read so far, then the size once the blob is kept. Resolves to
   * its ID.
   */
  async putStream(
    name: string | undefined,
    source: ReadableStream<Uint8Array>,
    onProgress?: Progress,
  ): Promise<BlobId> {
    const reader = source.getReader();
    const pull = async (): Promise<Uint8Array | undefined> => {
      const { done, value } = await reader.read();
      return done ? undefined : value;
    };
    try {
      return await callAsync(() => this.raw().putStream(name, pull, onProgress) as Promise<BlobId>);
    } catch (error) {
      await reader.cancel(error).catch(() => {});
      throw error;
    } finally {
      reader.releaseLock();
    }
  }

  /**
   * Puts a blob from a `Blob` or a `File`, with a name if given, without holding it whole: the
   * file is read twice through `slice`, once for the blob's ID and once to seal it a chunk at a
   * time, so the put holds a few chunks in WebAssembly memory whatever the file's size.
   * `onProgress` reports the bytes sealed so far, with the file's size. A file that changes
   * while it is put rejects with `Changed`. Resolves to its ID.
   */
  putFile(name: string | undefined, file: Blob, onProgress?: Progress): Promise<BlobId> {
    const readAt = async (offset: number, length: number): Promise<Uint8Array> =>
      new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
    return callAsync(() => this.raw().putAt(name, readAt, onProgress) as Promise<BlobId>);
  }

  /**
   * A blob's bytes as a stream, without holding them whole in memory. `onProgress` reports the
   * bytes opened so far. The stream errors if the blob cannot be read.
   */
  getStream(id: BlobId, onProgress?: Progress): ReadableStream<Uint8Array> {
    let wake: (() => void) | undefined;
    let cancelled = false;
    return new ReadableStream<Uint8Array>({
      start: (controller) => {
        const push = (chunk: Uint8Array): Promise<void> => {
          if (cancelled) return Promise.reject(new Error("the reader cancelled the stream"));
          controller.enqueue(chunk);
          if ((controller.desiredSize ?? 1) > 0) return Promise.resolve();
          return new Promise<void>((resolve) => {
            wake = resolve;
          });
        };
        callAsync(() => this.raw().getStream(id, push, onProgress) as Promise<void>).then(
          () => {
            if (!cancelled) controller.close();
          },
          (error: unknown) => {
            if (!cancelled) controller.error(error);
          },
        );
      },
      pull: () => {
        const resume = wake;
        wake = undefined;
        resume?.();
      },
      cancel: () => {
        cancelled = true;
        const resume = wake;
        wake = undefined;
        resume?.();
      },
    });
  }

  /**
   * A blob's bytes; `undefined` while this device does not hold them whole yet. A reference reads
   * like any blob.
   */
  get(id: BlobId): Promise<Uint8Array | undefined> {
    return callAsync(() => this.raw().get(id) as Promise<Uint8Array | undefined>);
  }

  /**
   * Puts a reference to a blob of `source`, a blob stream of another space of the same library: the
   * file is not stored again, and this space's readers read it without joining the source. Resolves
   * to the new blob's ID; rejects with `other_library` when the spaces are billed to different
   * libraries, where the file is copied instead.
   */
  referenceFrom(source: Blobs, id: BlobId): Promise<BlobId> {
    return callAsync(() => this.raw().referenceFrom(Handle.rawOf(source), id) as Promise<BlobId>);
  }

  /** A blob's details: its name, media type and size, and for a reference the space that stores it. */
  info(id: BlobId): Promise<BlobDetails> {
    return callAsync(() => this.raw().info(id) as Promise<BlobDetails>);
  }

  /**
   * Removes a blob from the stream. A reference's file goes once the peers collect what listed it,
   * unless its source or another space still uses it.
   */
  remove(id: BlobId): Promise<void> {
    return callAsync(() => this.raw().remove(id) as Promise<void>);
  }
}
