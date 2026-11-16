/**
 * The entry `@frasil/client/index`: the whole client, from a build of the module that also holds
 * the index, a typed SQLite cache over the device's spaces, kept in the origin-private file system
 * and encrypted at rest. Open the device and the index in a dedicated worker, where OPFS gives
 * synchronous access handles; a page can query the worker's index through
 * {@link serveIndex} and {@link IndexClient}.
 *
 * Each table is fed by the spaces of one kind, and every space of that kind that this device
 * reads puts its rows there. The tables are described by a manifest: the JSON a Rust schema's
 * `Schema::manifest` writes, or one written by hand. {@link manifestToTypeScript} gives its row
 * types.
 *
 * ```ts
 * // worker.ts
 * import { Device, Index, serveIndex, Storage } from "@frasil/client/index";
 *
 * const device = await Device.open(Storage.indexedDb("my-app"), unlockKey);
 * const index = await Index.open(device, "my-app", manifest);
 * void index.follow();
 * serveIndex(index, self);
 *
 * // page.ts
 * const index = new IndexClient(worker);
 * const open = index.watch("SELECT title FROM task WHERE done = 0");
 * ```
 *
 * Use this entry, not the default one, for every Frasil object of that worker: the index works
 * with devices of its own build of the module.
 *
 * @module
 */

import type { Device } from "./device.js";
import { FrasilError } from "./errors.js";
import { type Observable, type Snapshot, structurallyEqual } from "./observe.js";
import { callAsync, follow, Handle, raw } from "./runtime.js";
import type { SpaceId } from "./space.js";

export * from "./index.js";

/** A value of a query's row, or a parameter: integers beyond 2^53 are `bigint`s. */
export type SqlValue = null | number | bigint | string | Uint8Array;

/** A query's row: one property per column. Parameters may also be booleans, as 1 and 0. */
export type IndexRow = { readonly [column: string]: SqlValue };

/** A query's parameter. */
export type SqlParam = SqlValue | boolean | undefined;

/** A store of a live query, which follows its feed while subscribed. */
class WatchStore<R> implements Observable<R[]> {
  readonly #start: () => { next(): Promise<unknown>; free(): void };
  readonly #listeners = new Set<() => void>();
  #snapshot: Snapshot<R[]> = Object.freeze({ status: "loading", value: undefined });
  #stop: (() => void) | undefined;

  constructor(start: () => { next(): Promise<unknown>; free(): void }) {
    this.#start = start;
  }

  get = (): Snapshot<R[]> => this.#snapshot;

  subscribe = (listener: () => void): (() => void) => {
    this.#listeners.add(listener);
    if (this.#stop === undefined) {
      this.#stop = follow<R[]>(
        this.#start(),
        (rows) => {
          if (this.#snapshot.status === "ready" && structurallyEqual(this.#snapshot.value, rows)) {
            return;
          }
          this.#set(Object.freeze({ status: "ready", value: rows }));
        },
        (error) =>
          this.#set(Object.freeze({ status: "failed", value: this.#snapshot.value, error })),
      );
    }
    let subscribed = true;
    return () => {
      if (!subscribed) return;
      subscribed = false;
      this.#listeners.delete(listener);
      if (this.#listeners.size === 0) {
        this.#stop?.();
        this.#stop = undefined;
      }
    };
  };

  #set(snapshot: Snapshot<R[]>): void {
    this.#snapshot = snapshot;
    for (const listener of [...this.#listeners]) listener();
  }
}

/** The index of a device's spaces. Open it in a dedicated worker. */
export class Index extends Handle<raw.Index> {
  private constructor(value: raw.Index) {
    super(value, "Index");
  }

  /**
   * Opens the index of `device` under `name`, with the tables `manifest` describes, and brings it
   * up to date from the device's replicas. A cache of another schema, or one that does not open
   * under the device's key, is rebuilt, with no network. Only in a dedicated worker; rejects
   * otherwise.
   */
  static async open(device: Device, name: string, manifest: string | object): Promise<Index> {
    const text = typeof manifest === "string" ? manifest : JSON.stringify(manifest);
    return new Index(
      await callAsync(() => raw.Index.open(Handle.rawOf(device), name, text) as Promise<raw.Index>),
    );
  }

  /** The schema's manifest, as JSON. */
  get manifest(): string {
    return this.raw().manifest;
  }

  /** A count that grows each time the index changes a table. */
  get revision(): number {
    return this.raw().revision;
  }

  /** Runs a read-only query: its rows. A query that writes is refused. */
  query<R = IndexRow>(sql: string, params: readonly SqlParam[] = []): R[] {
    try {
      return this.raw().query(sql, [...params]) as R[];
    } catch (error) {
      throw asError(error);
    }
  }

  /**
   * A live query, as a store: it runs once subscribed, then again each time the index changes a
   * table it reads, and subscribers hear of its rows when they differ.
   */
  watch<R = IndexRow>(sql: string, params: readonly SqlParam[] = []): Observable<R[]> {
    return new WatchStore<R>(() => {
      try {
        return this.raw().watch(sql, [...params]);
      } catch (error) {
        throw asError(error);
      }
    });
  }

  /**
   * Calls `callback` with the names of the tables the index changes, each time it changes them.
   * Returns the function that stops it.
   */
  onTablesChange(callback: (tables: string[]) => void): () => void {
    return follow<string[]>(this.raw().tableChanges(), callback);
  }

  /** Brings the whole cache up to date. */
  sync(): Promise<void> {
    return callAsync(() => this.raw().sync() as Promise<void>);
  }

  /** Brings one space up to date. */
  refresh(space: SpaceId): Promise<void> {
    return callAsync(() => this.raw().refresh(space) as Promise<void>);
  }

  /** Drops the cache and reads every space again. */
  rebuild(): Promise<void> {
    return callAsync(() => this.raw().rebuild() as Promise<void>);
  }

  /**
   * Follows the device, keeping the cache current, until the device closes: a write refreshes the
   * rows it touched, any other change its space. A refresh that fails is retried with backoff, and
   * `onError` hears of it; the others go on.
   */
  follow(onError?: (message: string) => void): Promise<void> {
    return callAsync(() => this.raw().follow(onError) as Promise<void>);
  }
}

/** What the binding threw, as a `FrasilError`. */
function asError(error: unknown): unknown {
  if (error instanceof Error && error.name === "FrasilError") {
    const code = (error as Error & { code?: unknown }).code;
    return new FrasilError(typeof code === "string" ? code : "index", error.message);
  }
  return error;
}

// ---- Between a worker and a page ------------------------------------------------------------

/**
 * Where messages go and come from: a worker, the worker's global scope, or a `MessagePort`. Never
 * a `window`: other documents can post to it.
 */
export interface IndexPort {
  postMessage(message: unknown): void;
  addEventListener(type: "message", listener: (event: MessageEvent) => void): void;
  removeEventListener(type: "message", listener: (event: MessageEvent) => void): void;
}

/** A request of {@link IndexClient}. */
type Request =
  | { frasilIndex: number; op: "query"; sql: string; params: SqlParam[] }
  | { frasilIndex: number; op: "watch"; sql: string; params: SqlParam[] }
  | { frasilIndex: number; op: "unwatch" };

/** An answer of {@link serveIndex}. */
type Answer =
  | { frasilIndex: number; rows: unknown[] }
  | { frasilIndex: number; error: { code: string; message: string } };

/**
 * Answers the queries and live queries an {@link IndexClient} sends over `port`, from `index`.
 * Returns the function that stops it, and every live query with it.
 *
 * It checks no message's origin or source, and runs the SQL it receives, so `port` must reach only
 * your own code: a dedicated worker, its global scope, or one end of a `MessageChannel` you made.
 * Never pass `window`, a shared worker's port that other origins reach, or a `BroadcastChannel`.
 */
export function serveIndex(index: Index, port: IndexPort): () => void {
  const watches = new Map<number, () => void>();
  const answer = (message: Answer): void => port.postMessage(message);
  const failed = (id: number, error: unknown): void => {
    const code =
      error instanceof Error && "code" in error && typeof error.code === "string"
        ? error.code
        : "index";
    answer({
      frasilIndex: id,
      error: { code, message: String((error as Error)?.message ?? error) },
    });
  };
  const listener = (event: MessageEvent): void => {
    const request = event.data as Request | undefined;
    if (typeof request !== "object" || request === null || !("frasilIndex" in request)) return;
    const id = request.frasilIndex;
    try {
      if (request.op === "query") {
        answer({ frasilIndex: id, rows: index.query(request.sql, request.params) });
      } else if (request.op === "watch") {
        const store = index.watch(request.sql, request.params);
        const stop = store.subscribe(() => {
          const now = store.get();
          if (now.status === "ready") answer({ frasilIndex: id, rows: now.value ?? [] });
          else if (now.status === "failed") failed(id, now.error);
        });
        watches.set(id, stop);
      } else if (request.op === "unwatch") {
        watches.get(id)?.();
        watches.delete(id);
      }
    } catch (error) {
      failed(id, error);
    }
  };
  port.addEventListener("message", listener);
  return () => {
    port.removeEventListener("message", listener);
    for (const stop of watches.values()) stop();
    watches.clear();
  };
}
